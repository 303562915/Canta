-- Anonymous package-safety telemetry: RPC functions.
--
-- These reproduce the contract the client already speaks, so switching a build
-- to another backend is only a base URL and key change:
--
--   POST /rest/v1/rpc/challenge            {}                        -> {challenge, sig}
--   POST /rest/v1/rpc/record               {payload, challenge, sig, x}
--   POST /rest/v1/rpc/package_scores       {}                        -> [rows]
--   POST /rest/v1/rpc/package_scores_for   {p_rom, p_rom_version}    -> [rows]
--
-- Proof of work (util/Pow.kt on the client):
--   prefix = challenge || ':' || hex(sha256(payload)) || ':' || x
--   accept when the first 8 bytes of sha256(prefix), big-endian, are below
--   floor(2^64 / (10000 * number_of_events)) -- roughly 10k hashes per event.

/** 2^64, as numeric: heads are compared unsigned. */
create or replace function public.pow_space() returns numeric
language sql immutable as $$ select 18446744073709551616::numeric $$;

/** Smallest acceptable hash head for a batch of [n_events] events. */
create or replace function public.pow_target(n_events integer) returns numeric
language sql immutable as $$
    select case
        when n_events is null or n_events < 1 then null
        else floor(public.pow_space() / (10000::numeric * n_events))
    end
$$;

/** Unsigned big-endian value of the first 8 bytes of [digest]. */
create or replace function public.pow_head(digest bytea) returns numeric
language sql immutable as $$
    select coalesce(sum(get_byte(digest, i)::numeric * (256::numeric ^ (7 - i))), 0)
    from generate_series(0, 7) as i
$$;

/**
 * Verdict for one package on one ROM version. Thresholds are ours (the upstream
 * ones are not public); they are deliberately conservative: a verdict only turns
 * SAFE when most uninstalls survived a reboot and almost none came back.
 *
 *   too few uninstalls                    -> INSUFFICIENT
 *   15%+ put back by hand                 -> BOOTLOOP   (a rescue is the strongest signal)
 *   30%+ came back at all                 -> BOOTLOOP
 *   10%+ came back                        -> BREAKS
 *   half+ survived, <=2% came back        -> SAFE
 *   anything else                         -> UNCLEAR
 */
create or replace function public.verdict_of(
    uninstalls bigint, survived bigint, reinstalled bigint, restored bigint
) returns text language sql immutable as $$
    with n as (select greatest(uninstalls, 0)::numeric as u),
         x as (
             select u,
                    case when u = 0 then 0 else (reinstalled + restored) * 100 / u end as back_pct,
                    case when u = 0 then 0 else restored * 100 / u end                  as rescue_pct,
                    case when u = 0 then 0 else survived * 100 / u end                  as survived_pct
             from n
         )
    select case
        when u < 5                then 'INSUFFICIENT'
        when rescue_pct >= 15     then 'BOOTLOOP'
        when back_pct >= 30       then 'BOOTLOOP'
        when back_pct >= 10       then 'BREAKS'
        when survived_pct >= 50 and back_pct <= 2 then 'SAFE'
        else 'UNCLEAR'
    end
    from x
$$;

/** A fresh, single-use challenge with its token. */
create or replace function public.challenge() returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    token text;
    nonce text;
begin
    -- Old, never used challenges are dropped: they can no longer be redeemed anyway.
    delete from telemetry_challenges where created_at < now() - interval '1 hour';
    token := encode(sha256(convert_to(gen_random_uuid()::text || clock_timestamp()::text, 'utf8')), 'hex');
    nonce := encode(sha256(convert_to(token || 'canta', 'utf8')), 'hex');
    insert into telemetry_challenges (challenge, sig) values (token, left(nonce, 32));
    return jsonb_build_object('challenge', token, 'sig', left(nonce, 32));
end;
$$;

/**
 * Accepts one batch of events. Fails (and stores nothing) when the challenge is
 * unknown, already used, expired, or the proof of work does not check out.
 * Payload shape:
 *   {v, platform, device:{brand, rom, romVersion, sdk}, events:[{e, p, w, b}]}
 */
create or replace function public."record"(
    payload text, challenge text, sig text, x bigint
) returns jsonb
language plpgsql security definer set search_path = public as $$
#variable_conflict use_variable
declare
    row_challenge telemetry_challenges;
    body jsonb;
    n_events integer;
    head numeric;
    target numeric;
    prefix text;
    accepted integer;
begin
    if payload is null or challenge is null or sig is null or x is null then
        raise exception 'missing argument' using errcode = '22023';
    end if;

    select * into row_challenge from telemetry_challenges c
        where c.challenge = challenge for update;
    if not found
       or row_challenge.sig <> sig
       or row_challenge.used_at is not null
       or row_challenge.created_at < now() - interval '10 minutes' then
        raise exception 'invalid challenge' using errcode = '28000';
    end if;

    body := payload::jsonb;
    -- Shape first: a malformed payload must not burn the challenge either.
    if (body->>'v')::int is distinct from 1 then
        raise exception 'unsupported payload version' using errcode = '22023';
    end if;
    n_events := jsonb_array_length(coalesce(body->'events', '[]'::jsonb));
    if n_events < 1 or n_events > 250 then
        raise exception 'bad event count: %', n_events using errcode = '22023';
    end if;

    -- Proof of work, computed exactly like the client does.
    prefix := challenge || ':' || encode(sha256(convert_to(payload, 'utf8')), 'hex') || ':' || x::text;
    head := pow_head(sha256(convert_to(prefix, 'utf8')));
    target := pow_target(n_events);
    if head >= target then
        raise exception 'proof of work failed' using errcode = '28000';
    end if;

    insert into telemetry_events (platform, pkg, kind, cohort_week, batch_bucket, brand, rom, rom_version, sdk)
    select coalesce(nullif(body->>'platform', ''), 'unknown'),
           e->>'p',
           e->>'e',
           (e->>'w')::date,
           e->>'b',
           coalesce(nullif(body->'device'->>'brand', ''), 'unknown'),
           coalesce(nullif(body->'device'->>'rom', ''), 'unknown'),
           coalesce((body->'device'->>'romVersion')::int, 0),
           coalesce((body->'device'->>'sdk')::int, 0)
    from jsonb_array_elements(body->'events') as e
    where e ? 'p' and e ? 'e' and e ? 'w' and e ? 'b';

    get diagnostics accepted = row_count;
    if accepted = 0 then
        raise exception 'no usable events' using errcode = '22023';
    end if;

    update telemetry_challenges set used_at = now() where telemetry_challenges.challenge = challenge;

    return jsonb_build_object('ok', true, 'accepted', accepted);
exception
    when check_violation or invalid_text_representation then
        raise exception 'invalid event value' using errcode = '22023';
end;
$$;

/** Rows for the overall scores (all ROMs). */
create or replace function public.package_scores() returns table (
    pkg text, uninstalls bigint, small_batch boolean, verdict text, updated_at timestamptz, main_rom text
) language sql stable security definer set search_path = public as $$
    select a.pkg,
           a.uninstalls,
           a.small_batch_uninstalls * 2 >= a.uninstalls as small_batch,
           verdict_of(a.uninstalls, a.survived, a.reinstalled, a.restored) as verdict,
           a.updated_at,
           (select m.rom from telemetry_package_aggregate m
             where m.pkg = a.pkg group by m.rom order by sum(m.uninstalls) desc, m.rom limit 1) as main_rom
    from (
        select pkg,
               sum(uninstalls)::bigint   as uninstalls,
               sum(survived)::bigint     as survived,
               sum(reinstalled)::bigint  as reinstalled,
               sum(restored)::bigint     as restored,
               sum(small_batch_uninstalls)::bigint as small_batch_uninstalls,
               max(updated_at)           as updated_at
        from telemetry_package_aggregate
        group by pkg
    ) a
$$;

/**
 * Rows for one ROM: [p_rom_version] = -1 means the whole family (every version),
 * anything else is that exact ROM major version. The client asks for both.
 */
create or replace function public.package_scores_for(
    p_rom text, p_rom_version integer
) returns table (
    pkg text, uninstalls bigint, small_batch boolean, verdict text, updated_at timestamptz
) language sql stable security definer set search_path = public as $$
    select a.pkg,
           a.uninstalls,
           a.small_batch_uninstalls * 2 >= a.uninstalls as small_batch,
           verdict_of(a.uninstalls, a.survived, a.reinstalled, a.restored) as verdict,
           a.updated_at
    from (
        select pkg,
               sum(uninstalls)::bigint   as uninstalls,
               sum(survived)::bigint     as survived,
               sum(reinstalled)::bigint  as reinstalled,
               sum(restored)::bigint     as restored,
               sum(small_batch_uninstalls)::bigint as small_batch_uninstalls,
               max(updated_at)           as updated_at
        from telemetry_package_aggregate
        where rom = p_rom
          and (p_rom_version = -1 or rom_version = p_rom_version)
        group by pkg
    ) a
$$;

/**
 * Drops raw events older than [keep_days] and expired challenges; the aggregates
 * are computed from the remaining events, so the window is the whole history of
 * a score. Schedule it, e.g. with pg_cron:
 *   select cron.schedule('purge-telemetry', '30 3 * * *', $$select public.purge_raw_events()$$);
 */
create or replace function public.purge_raw_events(keep_days integer default 35) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    events_dropped bigint;
    challenges_dropped bigint;
begin
    delete from telemetry_events where received_at < now() - make_interval(days => keep_days);
    get diagnostics events_dropped = row_count;
    delete from telemetry_challenges where created_at < now() - interval '1 day' or used_at < now() - interval '1 day';
    get diagnostics challenges_dropped = row_count;
    return jsonb_build_object('events', events_dropped, 'challenges', challenges_dropped);
end;
$$;

-- Callable through PostgREST by the app (the publishable/anon key) and nobody else.
revoke all on function public.challenge() from public;
revoke all on function public."record"(text, text, text, bigint) from public;
revoke all on function public.package_scores() from public;
revoke all on function public.package_scores_for(text, integer) from public;
revoke all on function public.purge_raw_events(integer) from public;

-- Supabase always has these roles; anywhere else the grants are skipped so the
-- migrations stay runnable against a plain PostgreSQL for testing.
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.challenge() to anon;
        grant execute on function public."record"(text, text, text, bigint) to anon;
        grant execute on function public.package_scores() to anon;
        grant execute on function public.package_scores_for(text, integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.challenge() to authenticated;
        grant execute on function public."record"(text, text, text, bigint) to authenticated;
        grant execute on function public.package_scores() to authenticated;
        grant execute on function public.package_scores_for(text, integer) to authenticated;
    end if;
end $$;
