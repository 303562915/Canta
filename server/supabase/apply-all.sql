-- 粘贴到 Supabase 控制台 → SQL 编辑器，一次执行（等价于依次跑三个迁移文件）。
-- 已执行过前两个的可只跑最后一段（社区方案）。

-- Anonymous package-safety telemetry: storage.
--
-- Wire-compatible with the client in composeApp (see util/Telemetry.kt and
-- util/Pow.kt): the app posts to /rest/v1/rpc/challenge and /rest/v1/rpc/record
-- and reads /rest/v1/rpc/package_scores and /rest/v1/rpc/package_scores_for.
--
-- Nothing here identifies a device: the payload carries only brand, ROM family,
-- ROM major version and API level, and the raw events are dropped after the
-- retention window (see the purge function).

create table if not exists public.telemetry_challenges (
    challenge  text primary key,
    sig        text not null,
    created_at timestamptz not null default now(),
    used_at    timestamptz
);

comment on table public.telemetry_challenges is
    'One row per proof-of-work challenge handed out; used_at makes each usable once.';

create index if not exists telemetry_challenges_created_idx
    on public.telemetry_challenges (created_at);

create table if not exists public.telemetry_events (
    id          bigserial primary key,
    received_at timestamptz not null default now(),
    -- 'android', 'desktop' or 'web' (the client's platform label)
    platform    text not null,
    pkg         text not null,
    kind        text not null,
    cohort_week date not null,
    batch_bucket text not null,
    brand       text not null,
    rom         text not null,
    rom_version integer not null,
    sdk         integer not null,
    constraint telemetry_events_kind_valid check (
        kind in ('uninstalled', 'survived_reboot', 'reinstalled', 'voided', 'restored')
    ),
    constraint telemetry_events_bucket_valid check (batch_bucket in ('1', '2-10', '11+'))
);

comment on table public.telemetry_events is
    'Raw anonymous events; wiped by purge_raw_events() after the retention window.';
comment on column public.telemetry_events.kind is
    'uninstalled / survived_reboot / reinstalled / voided / restored (the last one: put back by hand).';

create index if not exists telemetry_events_pkg_idx on public.telemetry_events (pkg);
create index if not exists telemetry_events_pkg_rom_idx on public.telemetry_events (pkg, rom, rom_version);
create index if not exists telemetry_events_received_idx on public.telemetry_events (received_at);

-- The tables are only reachable through the RPC functions below.
alter table public.telemetry_challenges enable row level security;
alter table public.telemetry_events enable row level security;

-- No policies on purpose: anon and authenticated get nothing from the tables.

-- Aggregated scores. Recomputed on read (there is not enough data for that to
-- matter yet); replace with a materialized view if the tables grow.
create or replace view public.telemetry_package_aggregate as
select
    pkg,
    rom,
    rom_version,
    count(*) filter (where kind = 'uninstalled')                    as uninstalls,
    count(*) filter (where kind = 'survived_reboot')                 as survived,
    count(*) filter (where kind = 'reinstalled')                     as reinstalled,
    count(*) filter (where kind = 'restored')                        as restored,
    count(*) filter (where kind = 'uninstalled' and batch_bucket <> '11+') as small_batch_uninstalls,
    max(received_at)                                                 as updated_at
from public.telemetry_events
group by pkg, rom, rom_version;


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


-- Community uninstall plans: what other owners of the *same* model and ROM version removed and
-- confirmed by a reboot. Only verified plans are listed, and only for the caller's device.
--
-- Run after 20261116120100_telemetry_rpc.sql (or use server/supabase/apply-all.sql).

create table if not exists public.plans (
    id              bigserial primary key,
    created_at      timestamptz not null default now(),
    -- Which device the plan is for; matching is exact, never "similar".
    brand           text not null,
    model           text not null,
    codename        text not null,
    rom             text not null,
    rom_version     integer not null,
    sdk             integer not null,
    title           text not null,
    note            text not null default '',
    packages        text[] not null,
    -- The uploader confirmed a reboot *after* removing these, and the phone booted.
    reboot_verified boolean not null default false,
    rebooted_at     timestamptz,
    -- Random id of the reporter, so one person cannot vote twice; not tied to hardware.
    reporter        text not null default ''
);

create index if not exists plans_device_idx on public.plans (model, codename, rom, rom_version);
create index if not exists plans_created_idx on public.plans (created_at);

create table if not exists public.plan_votes (
    plan_id    bigint not null references public.plans (id) on delete cascade,
    voter      text not null,
    created_at timestamptz not null default now(),
    primary key (plan_id, voter)
);

create table if not exists public.plan_comments (
    id         bigserial primary key,
    plan_id    bigint not null references public.plans (id) on delete cascade,
    author     text not null default '',
    body       text not null,
    created_at timestamptz not null default now()
);

create index if not exists plan_comments_plan_idx on public.plan_comments (plan_id);

alter table public.plans enable row level security;
alter table public.plan_votes enable row level security;
alter table public.plan_comments enable row level security;

/**
 * Verified plans for one device, most liked first. [p_codename] may be empty; then the match is
 * on model + ROM + ROM version, which is still the same phone family and build.
 */
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from plan_comments c where c.plan_id = p.id)::bigint,
           p.created_at, p.rebooted_at
    from plans p
    where p.reboot_verified
      and lower(p.model) = lower(p_model)
      and (p_codename = '' or lower(p.codename) = lower(p_codename))
      and p.rom = p_rom
      and p.rom_version = p_rom_version
    order by
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
    limit greatest(1, least(p_limit, 100))
$$;

/**
 * Stores one plan. [p_plan] must carry the device it was made on and `reboot_verified: true`
 * together with `rebooted_at`; a plan whose reboot was never confirmed is rejected, because the
 * whole point is not to hand people a list that bricks their phone.
 */
create or replace function public.plan_submit(p_plan jsonb) returns bigint
language plpgsql security definer set search_path = public as $$
declare
    new_id bigint;
    pkgs text[];
begin
    if coalesce((p_plan->>'reboot_verified')::boolean, false) is not true then
        raise exception 'plan not verified by a reboot' using errcode = '22023';
    end if;
    if p_plan->>'rebooted_at' is null then
        raise exception 'missing reboot time' using errcode = '22023';
    end if;
    select array_agg(value) into pkgs from jsonb_array_elements_text(p_plan->'packages') as value;
    if pkgs is null or array_length(pkgs, 1) is null or array_length(pkgs, 1) = 0 or array_length(pkgs, 1) > 200 then
        raise exception 'bad package list' using errcode = '22023';
    end if;

    insert into plans (brand, model, codename, rom, rom_version, sdk, title, note, packages,
                       reboot_verified, rebooted_at, reporter)
    values (coalesce(p_plan->>'brand', 'unknown'), coalesce(p_plan->>'model', 'unknown'),
            coalesce(p_plan->>'codename', ''), coalesce(p_plan->>'rom', 'unknown'),
            coalesce((p_plan->>'rom_version')::int, 0), coalesce((p_plan->>'sdk')::int, 0),
            left(coalesce(p_plan->>'title', 'Untitled'), 120), left(coalesce(p_plan->>'note', ''), 2000),
            pkgs, true, (p_plan->>'rebooted_at')::timestamptz, coalesce(p_plan->>'reporter', ''))
    returning id into new_id;
    return new_id;
end;
$$;

/** Adds the caller's vote and returns the new count; voting twice is a no-op. */
create or replace function public.plan_vote(p_id bigint, p_voter text) returns bigint
language plpgsql security definer set search_path = public as $$
begin
    if coalesce(p_voter, '') = '' then
        raise exception 'missing voter' using errcode = '22023';
    end if;
    insert into plan_votes (plan_id, voter) values (p_id, p_voter) on conflict do nothing;
    return (select count(*) from plan_votes where plan_id = p_id);
end;
$$;

create or replace function public.plan_comment(p_id bigint, p_body text, p_author text default '') returns bigint
language plpgsql security definer set search_path = public as $$
declare new_id bigint;
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    insert into plan_comments (plan_id, author, body) values (p_id, left(coalesce(p_author, ''), 60), left(p_body, 1000))
    returning id into new_id;
    return new_id;
end;
$$;

create or replace function public.plan_comments_for(p_id bigint) returns table (
    author text, body text, created_at timestamptz
) language sql stable security definer set search_path = public as $$
    select author, body, created_at from plan_comments where plan_id = p_id order by created_at desc limit 200
$$;

revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_submit(jsonb) from public;
revoke all on function public.plan_vote(bigint, text) from public;
revoke all on function public.plan_comment(bigint, text, text) from public;
revoke all on function public.plan_comments_for(bigint) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_submit(jsonb) to anon;
        grant execute on function public.plan_vote(bigint, text) to anon;
        grant execute on function public.plan_comment(bigint, text, text) to anon;
        grant execute on function public.plan_comments_for(bigint) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_submit(jsonb) to authenticated;
        grant execute on function public.plan_vote(bigint, text) to authenticated;
        grant execute on function public.plan_comment(bigint, text, text) to authenticated;
        grant execute on function public.plan_comments_for(bigint) to authenticated;
    end if;
end $$;
