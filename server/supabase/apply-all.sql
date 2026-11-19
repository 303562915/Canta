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
-- plans_for gains columns in 20261118160000 below; drop the old shape first, otherwise
-- re-running this file fails with "cannot change return type of existing function".
drop function if exists public.plans_for(text, text, text, integer, integer);

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

-- ─────────────────────────────────────────────────────────────────────────────
-- 20261118160000_plan_test_and_owner.sql (test uploads + own-plan deletion)
-- ─────────────────────────────────────────────────────────────────────────────

-- Plans that belong to an install, test uploads, and deleting your own plan.
--
-- `owner` is the identity code the phone generated on first use (see DeviceIdentity in the app):
-- there is no account and no login, the device itself is the credential. `is_test` marks a plan
-- uploaded with the test password, i.e. one that was never proven by a reboot.
--
-- Run after 20261118120000_plans.sql (or use server/supabase/apply-all.sql).

alter table public.plans add column if not exists owner text not null default '';
alter table public.plans add column if not exists is_test boolean not null default false;

create index if not exists plans_owner_idx on public.plans (owner);

-- The return type changes, so the old function has to go before the new one can be created.
drop function if exists public.plans_for(text, text, text, integer, integer);

/**
 * Verified plans for one device, most liked first. [p_codename] may be empty; then the match is
 * on model + ROM + ROM version, which is still the same phone family and build.
 *
 * Real, reboot-proven plans sort before test plans whatever their votes: a test plan is a draft
 * to try the flow, not a recommendation.
 */
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from plan_comments c where c.plan_id = p.id)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test
    from plans p
    where p.reboot_verified
      and lower(p.model) = lower(p_model)
      and (p_codename = '' or lower(p.codename) = lower(p_codename))
      and p.rom = p_rom
      and p.rom_version = p_rom_version
    order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
    limit greatest(1, least(p_limit, 100))
$$;

/**
 * Stores one plan. [p_plan] must carry the device it was made on, an owner and
 * `reboot_verified: true` together with `rebooted_at`; a plan whose reboot was never confirmed is
 * rejected, because the whole point is not to hand people a list that bricks their phone. A test
 * upload reaches the same door with `test: true` and is stored flagged, so it can be told apart.
 */
create or replace function public.plan_submit(p_plan jsonb) returns bigint
language plpgsql security definer set search_path = public as $$
declare
    new_id bigint;
    pkgs text[];
    plan_owner text;
begin
    if coalesce((p_plan->>'reboot_verified')::boolean, false) is not true then
        raise exception 'plan not verified by a reboot' using errcode = '22023';
    end if;
    if p_plan->>'rebooted_at' is null then
        raise exception 'missing reboot time' using errcode = '22023';
    end if;
    plan_owner := left(coalesce(p_plan->>'owner', ''), 120);
    select array_agg(value) into pkgs from jsonb_array_elements_text(p_plan->'packages') as value;
    if pkgs is null or array_length(pkgs, 1) is null or array_length(pkgs, 1) = 0 or array_length(pkgs, 1) > 200 then
        raise exception 'bad package list' using errcode = '22023';
    end if;

    insert into plans (brand, model, codename, rom, rom_version, sdk, title, note, packages,
                       reboot_verified, rebooted_at, reporter, owner, is_test)
    values (coalesce(p_plan->>'brand', 'unknown'), coalesce(p_plan->>'model', 'unknown'),
            coalesce(p_plan->>'codename', ''), coalesce(p_plan->>'rom', 'unknown'),
            coalesce((p_plan->>'rom_version')::int, 0), coalesce((p_plan->>'sdk')::int, 0),
            left(coalesce(p_plan->>'title', 'Untitled'), 120), left(coalesce(p_plan->>'note', ''), 2000),
            pkgs, true, (p_plan->>'rebooted_at')::timestamptz,
            left(coalesce(p_plan->>'reporter', plan_owner), 120), plan_owner,
            coalesce((p_plan->>'test')::boolean, false))
    returning id into new_id;
    return new_id;
end;
$$;

/**
 * Deletes a plan this owner uploaded and returns whether anything was deleted.
 *
 * The owner has to match: an empty or foreign owner deletes nothing, so one install cannot remove
 * another's plan. Votes and comments go with it through the foreign keys.
 */
create or replace function public.plan_delete(p_id bigint, p_owner text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
begin
    if coalesce(p_owner, '') = '' then
        return false;
    end if;
    delete from plans where id = p_id and owner = p_owner;
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_submit(jsonb) from public;
revoke all on function public.plan_delete(bigint, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_submit(jsonb) to anon;
        grant execute on function public.plan_delete(bigint, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_submit(jsonb) to authenticated;
        grant execute on function public.plan_delete(bigint, text) to authenticated;
    end if;
end $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 20261118180000_user_numbers.sql (identity numbers from 10000)
-- ─────────────────────────────────────────────────────────────────────────────

-- Device identities with a number the phone remembers, starting at 10000.
--
-- There is no account and no login screen: the app keeps a random token in its settings and asks
-- for the row that token owns. The first call creates that row and hands back its id — 10000 for
-- the first install, 10001 for the next — and from then on the phone knows "I am #10000" and
-- sends that number as the owner of its plans. The token stays the secret: deleting a plan needs
-- both the number and the token, so guessing a number is not enough.
--
-- Run after 20261118160000_plan_test_and_owner.sql (or use server/supabase/apply-all.sql).

create table if not exists public.canta_users (
    id           bigint generated by default as identity (start with 10000) primary key,
    token        text not null unique,
    model        text not null default '',
    codename     text not null default '',
    created_at   timestamptz not null default now(),
    last_seen_at timestamptz not null default now()
);

create index if not exists canta_users_seen_idx on public.canta_users (last_seen_at desc);

alter table public.canta_users enable row level security;

/**
 * Returns the number belonging to [p_token], creating it on first sight.
 *
 * The number is what the app shows ("身份码 #10000") and what it sends as the owner of a plan;
 * the token is what proves the number is really this phone's. A token too short to be one of ours
 * is refused rather than stored.
 */
create or replace function public.user_login(
    p_token text, p_model text default '', p_codename text default ''
) returns bigint
language plpgsql security definer set search_path = public as $$
declare
    uid bigint;
begin
    if length(coalesce(p_token, '')) < 8 then
        raise exception 'bad token' using errcode = '22023';
    end if;
    select id into uid from canta_users where token = p_token;
    if uid is not null then
        update canta_users
           set last_seen_at = now(),
               model = coalesce(nullif(left(p_model, 80), ''), model),
               codename = coalesce(nullif(left(p_codename, 80), ''), codename)
         where id = uid;
        return uid;
    end if;
    insert into canta_users (token, model, codename)
    values (left(p_token, 120), left(coalesce(p_model, ''), 80), left(coalesce(p_codename, ''), 80))
    on conflict (token) do nothing
    returning id into uid;
    -- Two phones racing with the same token: the loser reads the winner's row.
    if uid is null then
        select id into uid from canta_users where token = p_token;
    end if;
    return uid;
end;
$$;

/**
 * Deletes a plan this identity uploaded. [p_owner] is the number, [p_token] is the secret that
 * proves it: a number alone (or somebody else's) deletes nothing.
 */
drop function if exists public.plan_delete(bigint, text);

create or replace function public.plan_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
begin
    if coalesce(p_owner, '') = '' or coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.id::text = p_owner and u.token = p_token) then
        return false;
    end if;
    delete from plans where id = p_id and owner = p_owner;
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

revoke all on function public.user_login(text, text, text) from public;
revoke all on function public.plan_delete(bigint, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.user_login(text, text, text) to anon;
        grant execute on function public.plan_delete(bigint, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.user_login(text, text, text) to authenticated;
        grant execute on function public.plan_delete(bigint, text, text) to authenticated;
    end if;
end $$;

-- 20261119100000_profile_names.sql
-- A display name for each identity, synced through the backend.
--
-- The app has no accounts: a phone owns a random token, and the number that token got (see
-- 20261118180000_user_numbers.sql) is its identity. This migration adds the one thing that is
-- worth syncing between installs: the name the user picked in Settings. Reviews and comments are
-- signed with it, and the avatar next to them is just its first character.
--
-- Both calls answer {id, name}, so a client learns the number and the name in one round trip and
-- never has to guess whether it is signed in.
--
-- Run after 20261118180000_user_numbers.sql (or use server/supabase/apply-all.sql).

alter table public.canta_users
    add column if not exists name text not null default '';

/** The longest name stored; the app stops the user well before this. */
create or replace function public.canta_user_name_max() returns integer
language sql immutable as $$ select 24 $$;

/**
 * Identity and name for [p_token], creating the row on first sight (which also creates the
 * number, starting at 10000). Returns null for a token too short to be one of ours.
 */
create or replace function public.profile_get(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid  bigint;
    unam text;
begin
    if length(coalesce(p_token, '')) < 8 then
        return null;
    end if;
    select id, name into uid, unam from canta_users where token = left(p_token, 120);
    if uid is null then
        insert into canta_users (token) values (left(p_token, 120))
        on conflict (token) do nothing
        returning id into uid;
        if uid is null then
            select id into uid from canta_users where token = left(p_token, 120);
        end if;
        unam := '';
    end if;
    update canta_users set last_seen_at = now() where id = uid;
    return jsonb_build_object('id', uid, 'name', coalesce(unam, ''));
end;
$$;

/**
 * Stores [p_name] for [p_token] and answers the row it wrote, so the phone shows exactly what the
 * backend kept. An empty name clears it, which brings back the install code as the display name.
 */
create or replace function public.profile_set_name(p_token text, p_name text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid  bigint;
    unam text;
begin
    if length(coalesce(p_token, '')) < 8 then
        raise exception 'bad token' using errcode = '22023';
    end if;
    unam := left(btrim(coalesce(p_name, '')), public.canta_user_name_max());
    insert into canta_users (token, name) values (left(p_token, 120), unam)
    on conflict (token) do update
        set name = excluded.name,
            last_seen_at = now()
    returning id, name into uid, unam;
    return jsonb_build_object('id', uid, 'name', unam);
end;
$$;

revoke all on function public.profile_get(text) from public;
revoke all on function public.profile_set_name(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.profile_get(text) to anon;
        grant execute on function public.profile_set_name(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.profile_get(text) to authenticated;
        grant execute on function public.profile_set_name(text, text) to authenticated;
    end if;
end $$;

-- 20261119110000_device_identity.sql
-- Keeps a phone's identity across an uninstall.
--
-- The identity is a random token the phone stores, so uninstalling the app throws it away and the
-- next install would look like a new person with a new number. This migration binds the token to a
-- device key — a hash the app computes from `ANDROID_ID` and the build fingerprint, never a raw
-- hardware identifier — so a reinstall can ask "which token does this phone own?" and get its old
-- one back, with its numbers, plans and name.
--
-- The token stays the secret: the device key is only a lookup key, and it is only ever used to hand
-- the token back to the phone that produced it. A factory reset, or another phone, is a new key and
-- therefore a new identity — that is the intended limit.
--
-- Run after 20261119100000_profile_names.sql (or use server/supabase/apply-all.sql).

create table if not exists public.canta_device_keys (
    device_key text primary key,
    token      text not null,
    created_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now()
);

alter table public.canta_device_keys enable row level security;

/**
 * Answers {token, id, name} for whoever is calling.
 *
 * [p_device_key] is the lookup: when this phone already bound a token, that token wins and the one
 * the caller just generated is dropped by the caller, which adopts the answer. A fresh device key
 * is bound to [p_token]. Both paths end with a `canta_users` row, so the number and the name come
 * back in the same round trip and the app never has to guess whether it is signed in.
 *
 * An empty [p_device_key] keeps working: the call then behaves like `profile_get` and the install
 * keeps its token (web builds have no stable device value).
 */
create or replace function public.identity_bind(p_token text, p_device_key text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid       bigint;
    unam      text;
    key_token text;
    key_hash  text;
    use_token text;
begin
    if length(coalesce(p_token, '')) < 8 then
        raise exception 'bad token' using errcode = '22023';
    end if;

    key_hash := nullif(left(btrim(coalesce(p_device_key, '')), 128), '');
    if key_hash is not null then
        select token into key_token from canta_device_keys where device_key = key_hash;
        if key_token is not null then
            update canta_device_keys set last_seen_at = now() where device_key = key_hash;
            use_token := key_token;
        else
            insert into canta_device_keys (device_key, token)
            values (key_hash, left(p_token, 120))
            on conflict (device_key) do nothing;
            -- Two installs racing on one phone: the loser reads the winner's binding.
            select token into key_token from canta_device_keys where device_key = key_hash;
            use_token := coalesce(key_token, left(p_token, 120));
        end if;
    else
        use_token := left(p_token, 120);
    end if;

    select id, name into uid, unam from canta_users where token = use_token;
    if uid is null then
        insert into canta_users (token) values (use_token)
        on conflict (token) do nothing
        returning id into uid;
        if uid is null then
            select id into uid from canta_users where token = use_token;
        end if;
        unam := '';
    end if;
    update canta_users set last_seen_at = now() where id = uid;

    return jsonb_build_object('token', use_token, 'id', uid, 'name', coalesce(unam, ''));
end;
$$;

revoke all on function public.identity_bind(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.identity_bind(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.identity_bind(text, text) to authenticated;
    end if;
end $$;


-- ===================================================================
-- 20261119120000_package_votes.sql
-- ===================================================================

-- "Can this package be removed?" — a two-sided vote, recorded per package and per device.
--
-- A plan like (`plan_vote`) says "this set of removals was ok on this phone". This table is the
-- other half: every owner can say, for one package, whether *their* phone was fine without it or
-- not. Both sides are counted, because "12 people removed it and nothing broke" and "3 people
-- removed it and it bootlooped" are what tells a reader whether to try it.
--
-- Votes are stored with the device they were cast on, so the app can show "on your model and ROM
-- version" and "on all devices" side by side. One vote per (package, voter): a second vote replaces
-- the first, which is how someone changes their mind.
--
-- Run after 20261119110000_device_identity.sql (or use server/supabase/apply-all.sql).

create table if not exists public.package_votes (
    pkg         text not null,
    -- The install that voted: its identity number, or a per-install id before it has one.
    voter       text not null,
    -- true: the phone was fine without it. false: removing it broke something.
    can_remove  boolean not null,
    -- The device the vote was cast on; empty when it was unknown.
    brand       text not null default '',
    model       text not null default '',
    codename    text not null default '',
    rom         text not null default '',
    rom_version integer not null default 0,
    sdk         integer not null default 0,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    primary key (pkg, voter)
);

create index if not exists package_votes_pkg_idx on public.package_votes (pkg);
create index if not exists package_votes_device_idx on public.package_votes (pkg, model, rom, rom_version);

alter table public.package_votes enable row level security;

/** Counts both sides for [p_pkg], in two scopes: this device, and every device. */
create or replace function public.package_vote_counts(
    p_pkg text, p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0
) returns jsonb language sql stable security definer set search_path = public as $$
    with scoped as (
        select v.can_remove,
               v.model, v.codename, v.rom, v.rom_version
        from package_votes v
        where v.pkg = p_pkg
    ), device as (
        select can_remove from scoped
        where lower(model) = lower(coalesce(p_model, ''))
          and rom = coalesce(p_rom, '')
          and rom_version = coalesce(p_rom_version, 0)
          and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
    )
    select jsonb_build_object(
        'yes', (select count(*) from device where can_remove),
        'no', (select count(*) from device where not can_remove),
        'all_yes', (select count(*) from scoped where can_remove),
        'all_no', (select count(*) from scoped where not can_remove)
    )
$$;

/**
 * Records what [p_voter] says about [p_pkg] on the device it names, and answers the fresh counts
 * in the same shape as [package_vote_counts].
 *
 * The new vote replaces an earlier one by the same voter, so "I was wrong" is one tap, not a
 * support ticket. An empty voter is rejected: there has to be something to count once.
 */
create or replace function public.package_vote(
    p_pkg text, p_voter text, p_can_remove boolean,
    p_brand text default '', p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0, p_sdk integer default 0
) returns jsonb language plpgsql security definer set search_path = public as $$
begin
    if length(coalesce(p_pkg, '')) = 0 then
        raise exception 'missing package' using errcode = '22023';
    end if;
    if length(coalesce(p_voter, '')) = 0 then
        raise exception 'missing voter' using errcode = '22023';
    end if;

    insert into package_votes (pkg, voter, can_remove, brand, model, codename, rom, rom_version, sdk)
    values (left(p_pkg, 200), left(p_voter, 120), p_can_remove,
            left(coalesce(p_brand, ''), 60), left(coalesce(p_model, ''), 80),
            left(coalesce(p_codename, ''), 80), left(coalesce(p_rom, ''), 60),
            coalesce(p_rom_version, 0), coalesce(p_sdk, 0))
    on conflict (pkg, voter) do update
        set can_remove = excluded.can_remove,
            brand = excluded.brand,
            model = excluded.model,
            codename = excluded.codename,
            rom = excluded.rom,
            rom_version = excluded.rom_version,
            sdk = excluded.sdk,
            updated_at = now();

    return public.package_vote_counts(p_pkg, p_model, p_codename, p_rom, p_rom_version);
end;
$$;

revoke all on function public.package_vote_counts(text, text, text, text, integer) from public;
revoke all on function public.package_vote(text, text, boolean, text, text, text, text, integer, integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to anon;
        grant execute on function public.package_vote(text, text, boolean, text, text, text, text, integer, integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to authenticated;
        grant execute on function public.package_vote(text, text, boolean, text, text, text, text, integer, integer) to authenticated;
    end if;
end $$;


-- Comment threads: one table for every comment the community pages show.
--
-- Until now comments only existed under a plan (`plan_comments`) and could not be answered, which
-- made "did anyone reply to what I wrote?" impossible to ask. This migration puts every comment in
-- one table — plans and app pages alike — gives each one a `parent_id` so a comment can be answered,
-- and adds the read side the app needs to manage its own comments:
--
--   * `comments_for`         one plan's or one app's thread, with the reply count of each comment
--   * `comment_add`          posts a comment, or a reply to one (replies never nest deeper than one)
--   * `comment_delete`       removes a comment the caller wrote, proven by identity number + token
--   * `comments_by_author`   what one identity wrote, with the plan/app it belongs to
--   * `comments_replies_to`  the replies other people left under that identity's comments
--
-- `kind` is 'plan' (target = the plan id as text) or 'app' (target = the package name). The
-- signature (`author`) is the name the person picked, so it can be renamed at any time; `author_id`
-- is the identity number behind it, and that is what ownership is checked against — otherwise
-- renaming yourself would lock you out of deleting your own comments.
--
-- The old `plan_comments` rows are carried over, and `plan_comment` / `plan_comments_for` are
-- re-pointed at the new table so an older app build keeps reading and writing the same thread.
--
-- Run after 20261119120000_package_votes.sql (or use server/supabase/apply-all.sql).

create table if not exists public.community_comments (
    id         bigserial primary key,
    -- 'plan' or 'app': which page the comment hangs under.
    kind       text not null default 'plan',
    -- The plan id (as text) or the package name.
    target     text not null,
    -- The comment this one answers; null for the comment that starts a thread.
    parent_id  bigint references public.community_comments (id) on delete cascade,
    -- The name it is signed with: the nickname from the settings, or "#10000".
    author     text not null default '',
    -- The identity number behind that name: what "my comments" and delete are keyed on.
    author_id  text not null default '',
    -- The phone it was written on, as the writer's app reported it: a comment about removing an app
    -- is only worth as much as the model it is about. The system is the ROM line people recognise
    -- ("HyperOS 2", "One UI 6"); the API level is deliberately not kept, because "36" reads as
    -- nothing while "HyperOS 2" reads as the build the advice is about.
    device_model text not null default '',
    system_name  text not null default '',
    body       text not null,
    created_at timestamptz not null default now()
);

create index if not exists community_comments_target_idx
    on public.community_comments (kind, target, created_at desc);
create index if not exists community_comments_parent_idx
    on public.community_comments (parent_id);
create index if not exists community_comments_author_idx
    on public.community_comments (author_id, created_at desc);

alter table public.community_comments enable row level security;

-- The plan comments written before this table existed are the same conversation: carry them over.
-- Those rows were signed with the uploader's number, which is also their identity number.
-- The `not exists` guard keeps the copy idempotent, so re-running this file changes nothing.
insert into public.community_comments (kind, target, author, author_id, body, created_at)
select 'plan', c.plan_id::text, c.author, c.author, c.body, c.created_at
  from public.plan_comments c
 where not exists (
     select 1
       from public.community_comments x
      where x.kind = 'plan'
        and x.target = c.plan_id::text
        and x.author = c.author
        and x.body = c.body
        and x.created_at = c.created_at
 );

/**
 * Verified plans for one device, most liked first — unchanged except that the comment count now
 * comes from the shared table, so a reply is counted like a comment.
 */
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test
    from plans p
    where p.reboot_verified
      and lower(p.model) = lower(p_model)
      and (p_codename = '' or lower(p.codename) = lower(p_codename))
      and p.rom = p_rom
      and p.rom_version = p_rom_version
    order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
    limit greatest(1, least(p_limit, 100))
$$;

/** The old plan comment writer: kept so an installed build keeps posting into the same thread. */
create or replace function public.plan_comment(p_id bigint, p_body text, p_author text default '') returns bigint
language plpgsql security definer set search_path = public as $$
declare new_id bigint;
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    insert into community_comments (kind, target, author, author_id, body)
    values ('plan', p_id::text, left(coalesce(p_author, ''), 60), left(coalesce(p_author, ''), 60),
            left(p_body, 1000))
    returning id into new_id;
    return new_id;
end;
$$;

/** The old plan comment reader, in its old shape, over the shared table. */
create or replace function public.plan_comments_for(p_id bigint) returns table (
    author text, body text, created_at timestamptz
) language sql stable security definer set search_path = public as $$
    select author, body, created_at
      from community_comments
     where kind = 'plan' and target = p_id::text
     order by created_at desc
     limit 200
$$;

/**
 * One thread, newest first, each comment with how many replies it collected.
 *
 * [p_target] is the plan id as text for `kind = 'plan'`, the package name for `kind = 'app'`.
 */
create or replace function public.comments_for(p_kind text, p_target text) returns table (
    id bigint, parent_id bigint, author text, body text, created_at timestamptz, replies bigint,
    device_model text, system_name text
) language sql stable security definer set search_path = public as $$
    select c.id, c.parent_id, c.author, c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint,
           c.device_model, c.system_name
      from community_comments c
     where c.kind = coalesce(nullif(p_kind, ''), 'plan')
       and c.target = coalesce(p_target, '')
     order by c.created_at desc
     limit 400
$$;

/**
 * Posts one comment, or one reply to [p_parent], and returns its id.
 *
 * [p_author] is the signature the page shows; [p_author_id] is the identity number behind it, which
 * is what lets the writer delete the comment after renaming themselves. A reply always lands
 * directly under the comment that started the thread: answering a reply answers the thread, so the
 * app only has to render two levels and nobody is quoted at six.
 */
create or replace function public.comment_add(
    p_kind text, p_target text, p_body text, p_author text default '',
    p_parent bigint default null, p_author_id text default '',
    p_model text default '', p_system text default ''
) returns bigint language plpgsql security definer set search_path = public as $$
declare
    new_id bigint;
    root_id bigint;
    kind text := coalesce(nullif(p_kind, ''), 'plan');
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    if length(coalesce(p_target, '')) = 0 then
        raise exception 'missing target' using errcode = '22023';
    end if;

    if p_parent is not null then
        select coalesce(c.parent_id, c.id) into root_id
          from community_comments c
         where c.id = p_parent
           and c.kind = kind
           and c.target = p_target;
        if root_id is null then
            raise exception 'parent comment not found' using errcode = '22023';
        end if;
    end if;

    insert into community_comments (kind, target, parent_id, author, author_id, body,
                                   device_model, system_name)
    values (kind, left(p_target, 200), root_id, left(coalesce(p_author, ''), 60),
            left(coalesce(p_author_id, ''), 60), left(p_body, 1000),
            left(coalesce(p_model, ''), 80), left(coalesce(p_system, ''), 60))
    returning id into new_id;
    return new_id;
end;
$$;

/**
 * Deletes one comment this identity wrote. [p_owner] is the identity number and [p_token] the
 * secret that proves it, exactly like `plan_delete`: a number alone deletes nothing.
 *
 * Ownership is checked on the number, not on the signature, so renaming yourself does not orphan
 * the comments you already wrote. Rows carried over from `plan_comments` have no number column of
 * their own — they were signed with it, so the signature is matched as a fallback.
 *
 * Replies hang off their comment (`on delete cascade`), so removing a thread starter removes the
 * conversation under it — which is what the person deleting it means.
 */
create or replace function public.comment_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
begin
    if coalesce(p_owner, '') = '' or coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.id::text = p_owner and u.token = p_token) then
        return false;
    end if;
    delete from community_comments c
     where c.id = p_id
       and (c.author_id = p_owner
            or (c.author_id = '' and (c.author = p_owner or c.author = '#' || p_owner)));
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

/**
 * What one identity wrote, newest first: the comments it started *and* the replies it left, each
 * with the plan or app it belongs to, so the app can list them and link back.
 *
 * [p_owner] is the identity number.
 */
create or replace function public.comments_by_author(p_owner text) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint
      from community_comments c
     where c.author_id = coalesce(p_owner, '')
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
     order by c.created_at desc
     limit 200
$$;

/**
 * The replies other people left under [p_owner]'s comments, newest first: the answer to "did
 * anybody react to what I wrote?".
 */
create or replace function public.comments_replies_to(p_owner text) returns table (
    id bigint, parent_id bigint, kind text, target text, title text,
    author text, body text, created_at timestamptz, parent_body text
) language sql stable security definer set search_path = public as $$
    select r.id, c.id,
           r.kind, r.target,
           coalesce((select left(p.title, 120) from plans p
                      where r.kind = 'plan' and p.id::text = r.target), '') as title,
           r.author, r.body, r.created_at, c.body
      from community_comments r
      join community_comments c on c.id = r.parent_id
     where (c.author_id = coalesce(p_owner, '')
            or (c.author_id = ''
                and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))))
       and r.author_id <> c.author_id
     order by r.created_at desc
     limit 200
$$;

revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_comment(bigint, text, text) from public;
revoke all on function public.plan_comments_for(bigint) from public;
revoke all on function public.comments_for(text, text) from public;
revoke all on function public.comment_add(text, text, text, text, bigint, text, text, text) from public;
revoke all on function public.comment_delete(bigint, text, text) from public;
revoke all on function public.comments_by_author(text) from public;
revoke all on function public.comments_replies_to(text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_comment(bigint, text, text) to anon;
        grant execute on function public.plan_comments_for(bigint) to anon;
        grant execute on function public.comments_for(text, text) to anon;
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to anon;
        grant execute on function public.comment_delete(bigint, text, text) to anon;
        grant execute on function public.comments_by_author(text) to anon;
        grant execute on function public.comments_replies_to(text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_comment(bigint, text, text) to authenticated;
        grant execute on function public.plan_comments_for(bigint) to authenticated;
        grant execute on function public.comments_for(text, text) to authenticated;
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to authenticated;
        grant execute on function public.comment_delete(bigint, text, text) to authenticated;
        grant execute on function public.comments_by_author(text) to authenticated;
        grant execute on function public.comments_replies_to(text) to authenticated;
    end if;
end $$;


-- ===================================================================
-- 20261119140000_comment_identity_and_vote_scope.sql
-- ===================================================================

-- Comments and votes, second pass: the identity fallback, and a vote scope that answers.
--
-- Two things the first pass got wrong for a phone whose number the backend had not handed out yet:
--
--   * A comment written before `identity_bind` answered was stored with `author_id` equal to the
--     install token's head (the client's fallback). `comments_by_author` only matched the number,
--     so the comment was invisible on "my comments" and `comment_delete` refused it. Both now also
--     match the token itself, which is the secret that proves the same thing.
--   * `package_vote_counts` scoped "this phone" on model + ROM + ROM version. When the app could not
--     read the model yet it sent empty strings, matched nothing, and the bar read 0 votes while
--     "all devices" had some. An empty model now means "no device scope yet": count everything.
--
-- Also adds `package_my_vote`, so the app page can show which side this install already picked
-- instead of trusting a value it remembered locally.
--
-- Run after 20261119130000_comment_threads.sql (or use server/supabase/apply-all.sql).

-- The one-argument versions are replaced by (owner, token): keeping both would make a call with
-- one argument ambiguous for PostgREST.
drop function if exists public.comments_by_author(text);
drop function if exists public.comments_replies_to(text);

/**
 * What one identity wrote, newest first: the comments it started *and* the replies it left.
 *
 * [p_owner] is the identity number; [p_token] is accepted as the same proof, because a comment
 * written before the number arrived was signed with the token instead. Both are matched, so a
 * thread does not split in two over when it was written.
 */
create or replace function public.comments_by_author(
    p_owner text, p_token text default ''
) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint
      from community_comments c
     where c.author_id in (
               coalesce(p_owner, ''),
               coalesce(p_token, ''),
               left(coalesce(p_token, ''), 16)
           )
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
     order by c.created_at desc
     limit 200
$$;

/** The replies other people left under [p_owner]'s comments; [p_token] proves the same identity. */
create or replace function public.comments_replies_to(
    p_owner text, p_token text default ''
) returns table (
    id bigint, parent_id bigint, kind text, target text, title text,
    author text, body text, created_at timestamptz, parent_body text
) language sql stable security definer set search_path = public as $$
    select r.id, c.id,
           r.kind, r.target,
           coalesce((select left(p.title, 120) from plans p
                      where r.kind = 'plan' and p.id::text = r.target), '') as title,
           r.author, r.body, r.created_at, c.body
      from community_comments r
      join community_comments c on c.id = r.parent_id
     where (c.author_id in (
                coalesce(p_owner, ''),
                coalesce(p_token, ''),
                left(coalesce(p_token, ''), 16)
            )
            or (c.author_id = ''
                and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))))
       and r.author_id <> c.author_id
       and r.author_id not in (coalesce(p_owner, ''), coalesce(p_token, ''))
     order by r.created_at desc
     limit 200
$$;

/**
 * Deletes one comment this identity wrote. [p_owner] is the identity number and [p_token] the
 * secret that proves it, exactly like `plan_delete`: a number alone deletes nothing. The token alone
 * is enough when the comment was written before the number arrived.
 */
create or replace function public.comment_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
begin
    if coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.token = p_token) then
        return false;
    end if;
    delete from community_comments c
     where c.id = p_id
       and (c.author_id = coalesce(p_owner, '')
            or c.author_id = p_token
            or c.author_id = left(p_token, 16)
            or (c.author_id = '' and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))));
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

/**
 * Counts both sides for [p_pkg], in two scopes: this device and every device.
 *
 * An empty [p_model] means the caller could not name its phone yet: there is no device scope to
 * report, so that scope is the whole table rather than a zero that reads like "nobody voted".
 */
create or replace function public.package_vote_counts(
    p_pkg text, p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0
) returns jsonb language sql stable security definer set search_path = public as $$
    with scoped as (
        select v.can_remove, v.model, v.codename, v.rom, v.rom_version
        from package_votes v
        where v.pkg = p_pkg
    ), device as (
        select can_remove from scoped
        where coalesce(p_model, '') = ''
           or (
               lower(model) = lower(coalesce(p_model, ''))
               and rom = coalesce(p_rom, '')
               and rom_version = coalesce(p_rom_version, 0)
               and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
           )
    )
    select jsonb_build_object(
        'yes', (select count(*) from device where can_remove),
        'no', (select count(*) from device where not can_remove),
        'all_yes', (select count(*) from scoped where can_remove),
        'all_no', (select count(*) from scoped where not can_remove)
    )
$$;

/** Which side [p_voter] picked for [p_pkg]: true, false, or null when it never voted. */
create or replace function public.package_my_vote(p_pkg text, p_voter text) returns boolean
language sql stable security definer set search_path = public as $$
    select v.can_remove
      from package_votes v
     where v.pkg = p_pkg
       and v.voter = coalesce(p_voter, '')
     limit 1
$$;

revoke all on function public.comments_by_author(text, text) from public;
revoke all on function public.comments_replies_to(text, text) from public;
revoke all on function public.comment_delete(bigint, text, text) from public;
revoke all on function public.package_vote_counts(text, text, text, text, integer) from public;
revoke all on function public.package_my_vote(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comments_by_author(text, text) to anon;
        grant execute on function public.comments_replies_to(text, text) to anon;
        grant execute on function public.comment_delete(bigint, text, text) to anon;
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to anon;
        grant execute on function public.package_my_vote(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comments_by_author(text, text) to authenticated;
        grant execute on function public.comments_replies_to(text, text) to authenticated;
        grant execute on function public.comment_delete(bigint, text, text) to authenticated;
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to authenticated;
        grant execute on function public.package_my_vote(text, text) to authenticated;
    end if;
end $$;


-- ===================================================================
-- 20261119150000_comment_add_variable_fix.sql
-- ===================================================================

-- Replies never landed: `comment_add` raised "column reference kind is ambiguous".
--
-- The function kept the requested kind in a variable called `kind` and then compared
-- `c.kind = kind` while selecting from the same table. PL/pgSQL resolves an unqualified name
-- against the query's columns as well as its own variables and refuses to guess, so every call
-- that carried a parent id — that is, every reply — failed before the insert. A comment on its own
-- worked, which is why the thread looked like it had no replies and not like it was broken.
--
-- The variable is `v_kind` now, and the body declares `#variable_conflict use_variable` so a future
-- parameter cannot reintroduce the same trap. Everything else is unchanged.
--
-- Run after 20261119140000_comment_identity_and_vote_scope.sql (or use server/supabase/apply-all.sql).

create or replace function public.comment_add(
    p_kind text, p_target text, p_body text, p_author text default '',
    p_parent bigint default null, p_author_id text default '',
    p_model text default '', p_system text default ''
) returns bigint language plpgsql security definer set search_path = public as $$
#variable_conflict use_variable
declare
    new_id bigint;
    root_id bigint;
    v_kind text := coalesce(nullif(p_kind, ''), 'plan');
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    if length(coalesce(p_target, '')) = 0 then
        raise exception 'missing target' using errcode = '22023';
    end if;

    if p_parent is not null then
        select coalesce(c.parent_id, c.id) into root_id
          from community_comments c
         where c.id = p_parent
           and c.kind = v_kind
           and c.target = p_target;
        if root_id is null then
            raise exception 'parent comment not found' using errcode = '22023';
        end if;
    end if;

    insert into community_comments (kind, target, parent_id, author, author_id, body,
                                   device_model, system_name)
    values (v_kind, left(p_target, 200), root_id, left(coalesce(p_author, ''), 60),
            left(coalesce(p_author_id, ''), 60), left(p_body, 1000),
            left(coalesce(p_model, ''), 80), left(coalesce(p_system, ''), 60))
    returning id into new_id;
    return new_id;
end;
$$;

revoke all on function public.comment_add(text, text, text, text, bigint, text, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to authenticated;
    end if;
end $$;


-- ===================================================================
-- 20261119160000_comment_author_backfill.sql
-- ===================================================================

-- "My comments" was empty because older rows were signed with a name, not a number.
--
-- `comment_add` stores the identity number in `author_id`, and everything the page reads matches on
-- it. Three batches of rows predate that: the ones carried over from `plan_comments` kept the
-- signature as their id, and the app used to send the display name ("开发者") or the token's code
-- ("E7638-DF160") instead of the number whenever `identity_bind` had not answered yet. Those rows
-- belong to somebody, and "my comments" has to find them.
--
-- Two parts:
--
--   * backfill — rewrite those ids into the number the same person owns, matched on the name they
--     picked and on the code their token produces (first 10 characters, 5+5, upper case);
--   * fallback — `comments_by_author`, `comments_replies_to` and `comment_delete` also accept a
--     non-numeric id that equals the caller's name, so a row written before this ran is still
--     listed and still deletable even if it could not be converted.
--
-- Run after 20261119150000_comment_add_variable_fix.sql (or use server/supabase/apply-all.sql).

-- The names people picked: an id that equals a name belongs to that account.
update public.community_comments c
   set author_id = u.id::text
  from public.canta_users u
 where u.name <> ''
   and c.author_id = u.name;

-- The install codes: `DeviceIdentity.codeOf` is the token's first 10 alphanumerics, upper-cased,
-- padded with '0' and cut into two groups of five. Rebuild the same string from the token.
with codes as (
    select u.id,
           upper(substr(rpad(clean, 10, '0'), 1, 5) || '-' || substr(rpad(clean, 10, '0'), 6, 5)) as code
      from (
          select id, upper(regexp_replace(token, '[^A-Za-z0-9]', '', 'g')) as clean
            from public.canta_users
      ) u
)
update public.community_comments c
   set author_id = codes.id::text
  from codes
 where c.author_id = codes.code;

/** What one identity wrote, newest first; a leftover name counts as that identity. */
create or replace function public.comments_by_author(
    p_owner text, p_token text default ''
) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint
      from community_comments c
     where c.author_id in (
               coalesce(p_owner, ''),
               coalesce(p_token, ''),
               left(coalesce(p_token, ''), 16)
           )
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
        -- A row that still carries a name instead of a number: accept it when the name is the one
        -- this identity picked. Only for non-numeric ids, so a real number is never matched by name.
        or (coalesce(p_owner, '') <> ''
            and c.author_id !~ '^[0-9]+$'
            and c.author = coalesce((select u.name from canta_users u
                                      where u.id::text = p_owner and u.name <> ''), ''))
     order by c.created_at desc
     limit 200
$$;

/** The replies other people left under [p_owner]'s comments; the same name fallback applies. */
create or replace function public.comments_replies_to(
    p_owner text, p_token text default ''
) returns table (
    id bigint, parent_id bigint, kind text, target text, title text,
    author text, body text, created_at timestamptz, parent_body text
) language sql stable security definer set search_path = public as $$
    select r.id, c.id,
           r.kind, r.target,
           coalesce((select left(p.title, 120) from plans p
                      where r.kind = 'plan' and p.id::text = r.target), '') as title,
           r.author, r.body, r.created_at, c.body
      from community_comments r
      join community_comments c on c.id = r.parent_id
     where (c.author_id in (
                coalesce(p_owner, ''),
                coalesce(p_token, ''),
                left(coalesce(p_token, ''), 16)
            )
            or (c.author_id = ''
                and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
            or (coalesce(p_owner, '') <> ''
                and c.author_id !~ '^[0-9]+$'
                and c.author = coalesce((select u.name from canta_users u
                                          where u.id::text = p_owner and u.name <> ''), '')))
       and r.author_id <> c.author_id
       and r.author_id not in (coalesce(p_owner, ''), coalesce(p_token, ''))
     order by r.created_at desc
     limit 200
$$;

/** Deletes one comment this identity wrote, including a row still signed with its name. */
create or replace function public.comment_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
    my_name text;
begin
    if coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.token = p_token) then
        return false;
    end if;
    select u.name into my_name from canta_users u where u.token = p_token;
    delete from community_comments c
     where c.id = p_id
       and (c.author_id = coalesce(p_owner, '')
            or c.author_id = p_token
            or c.author_id = left(p_token, 16)
            or (c.author_id = '' and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
            or (c.author_id !~ '^[0-9]+$'
                and my_name is not null and my_name <> '' and c.author = my_name));
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

revoke all on function public.comments_by_author(text, text) from public;
revoke all on function public.comments_replies_to(text, text) from public;
revoke all on function public.comment_delete(bigint, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comments_by_author(text, text) to anon;
        grant execute on function public.comments_replies_to(text, text) to anon;
        grant execute on function public.comment_delete(bigint, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comments_by_author(text, text) to authenticated;
        grant execute on function public.comments_replies_to(text, text) to authenticated;
        grant execute on function public.comment_delete(bigint, text, text) to authenticated;
    end if;
end $$;
