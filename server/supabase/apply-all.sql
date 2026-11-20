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
 * Verified plans for one device, most liked first — with the comment count from the shared table so
 * a reply counts like a comment, and with the name the uploader uses today, which is what the plan
 * card draws next to its letter avatar.
 */
drop function if exists public.plans_for(text, text, text, integer, integer);
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name
    from plans p
    left join canta_users u on u.id::text = p.owner
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
 * Counts both sides for [p_pkg], in two scopes: this device and every device, plus the per-system
 * breakdown of *this model only* — a Redmi K70 page must not offer a Redmi K30 Ultra's MIUI as if
 * this phone had run it.
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
    ), this_model as (
        -- The breakdown below is about this phone's own builds: votes from other models still
        -- count in all_yes / all_no, they just do not name a system under this phone.
        select * from scoped
        where coalesce(p_model, '') = ''
           or (
               lower(model) = lower(coalesce(p_model, ''))
               and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
           )
    ), device as (
        select can_remove from this_model
        where coalesce(p_model, '') = ''
           or (rom = coalesce(p_rom, '') and rom_version = coalesce(p_rom_version, 0))
    ), systems as (
        select case rom
                   when 'hyperos' then 'HyperOS'
                   when 'miui' then 'MIUI'
                   when 'oneui' then 'One UI'
                   when 'coloros' then 'ColorOS'
                   when 'realmeui' then 'realme UI'
                   when 'originos' then 'OriginOS'
                   when 'funtouch' then 'Funtouch OS'
                   when 'magicos' then 'MagicOS'
                   when 'emui' then 'EMUI'
                   when 'oxygenos' then 'OxygenOS'
                   when 'nothingos' then 'Nothing OS'
                   else 'Android'
               end || case when rom_version > 0 and rom not in ('', 'android')
                           then ' ' || rom_version else '' end as label,
               count(*) filter (where can_remove) as yes,
               count(*) filter (where not can_remove) as no
        from this_model
        group by 1
    )
    select jsonb_build_object(
        'yes', (select count(*) from device where can_remove),
        'no', (select count(*) from device where not can_remove),
        'all_yes', (select count(*) from scoped where can_remove),
        'all_no', (select count(*) from scoped where not can_remove),
        'systems', coalesce((
            select jsonb_object_agg(label, jsonb_build_object('yes', yes, 'no', no))
            from systems
        ), '{}'::jsonb)
    )
$$;

grant execute on function public.package_vote_counts(text, text, text, text, integer) to anon, authenticated;

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
-- The device catalog: which phones the community has plans for, on which builds, and how many
-- people joined each one.
--
-- The safety page used to speak about exactly one device — the caller's. This adds the other half:
-- a list the page can draw as chips (model → build), so a plan can be read before the same phone
-- arrives, and so "this model has nothing yet" is a fact the page can show instead of an empty
-- list. Nothing here changes what a plan is matched against; `plans_for` still serves the caller's
-- own build, and `plans_for_model` is the explicitly named door for browsing somebody else's.
--
-- People are counted per identity, with the same identity string on both sides:
--   'o:<number>'  — an install that owns the plan (or the user row it registered with)
--   'r:<reporter>' — a plan uploaded before owners existed
-- so one person who registered *and* uploaded counts once.
--
-- The model's display name is the one the uploader's ROM reported ("Redmi K70" instead of
-- "23113RKC6C"), stored from now on in `market_name`; older rows have none and fall back to the
-- retail model number, which is what the ROM called them.
--
-- Run after 20261119210000_comment_likes.sql (or use server/supabase/apply-all.sql).

alter table public.plans add column if not exists market_name text not null default '';

/**
 * Stores one plan, now with the model's marketing name when the uploader's ROM has one.
 *
 * The signature and every rule stay as they were: a reboot proof, an owner, at most 200 packages.
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

    insert into plans (brand, model, market_name, codename, rom, rom_version, sdk, title, note, packages,
                       reboot_verified, rebooted_at, reporter, owner, is_test)
    values (coalesce(p_plan->>'brand', 'unknown'), coalesce(p_plan->>'model', 'unknown'),
            left(coalesce(p_plan->>'market_name', ''), 80),
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

-- The shape grows by the device columns, and a return type cannot be replaced in place: every
-- function that answers with a plan row is dropped and rebuilt below, all with the same columns,
-- so the app keeps reading them through one parser.
drop function if exists public.plans_for(text, text, text, integer, integer);
drop function if exists public.plan_get(bigint);
drop function if exists public.plans_by_owner(text);

/**
 * Verified plans for one device, most liked first, now carrying the device each plan was made on.
 *
 * Matching is unchanged: exact model, optional codename, exact ROM and ROM version. The device
 * columns are what lets a row say "this plan is not for this phone" without a second call.
 */
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
    from plans p
    left join canta_users u on u.id::text = p.owner
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

/** One plan by id, for the pages that open a plan from a comment, a share code or another model. */
create or replace function public.plan_get(p_id bigint) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.id = p_id
     limit 1
$$;

/** Every plan one identity uploaded, whatever device it was matched to, newest first. */
create or replace function public.plans_by_owner(p_owner text) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
      from plans p
      left join canta_users u on u.id::text = p.owner
     where coalesce(p_owner, '') <> ''
       and p.owner = p_owner
     order by p.created_at desc
     limit 200
$$;

/**
 * The plans of another model — the browser behind the model chips.
 *
 * [p_brand] narrows the match when two makers sell a phone under one model string; an empty one
 * accepts every brand. [p_rom] empty (with [p_rom_version] 0) means "all builds of this model",
 * which is what the "全部" chip asks for. Matching is still exact on the model: this is not a
 * fuzzy search, it is the same phone sold somewhere else.
 */
create or replace function public.plans_for_model(
    p_model text, p_brand text default '', p_rom text default '', p_rom_version integer default 0,
    p_limit integer default 100
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.reboot_verified
       and coalesce(p_model, '') <> ''
       and lower(p.model) = lower(p_model)
       and (coalesce(p_brand, '') = '' or lower(p.brand) = lower(p_brand))
       and (
             coalesce(p_rom, '') = ''
             or (p.rom = p_rom and (coalesce(p_rom_version, 0) = 0 or p.rom_version = p_rom_version))
           )
     order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
     limit greatest(1, least(coalesce(p_limit, 100), 200))
$$;

/**
 * Every model the community has plans for, one row per build, with the counts the chips draw.
 *
 * `plans` / `people` are the row's own build; `model_plans` / `model_people` count the whole model
 * — the person who registered on the model but never uploaded is part of "加入", and the app shows
 * that number only when it is worth reading (more than a handful).
 */
create or replace function public.plan_catalog() returns table (
    brand text, model text, market_name text, rom text, rom_version integer,
    plans bigint, people bigint, model_plans bigint, model_people bigint
) language sql stable security definer set search_path = public as $$
    with builds as (
        select coalesce(nullif(p.brand, ''), 'unknown') as brand,
               p.model,
               p.rom,
               p.rom_version,
               count(*)::bigint as plans,
               count(distinct case
                        when coalesce(p.owner, '') <> '' then 'o:' || p.owner
                        else 'r:' || p.reporter
                      end)::bigint as people
          from plans p
         where coalesce(p.model, '') <> ''
         group by 1, 2, 3, 4
    ), models as (
        select b.brand,
               b.model,
               (select coalesce(p2.market_name, '')
                  from plans p2
                 where lower(p2.model) = lower(b.model)
                   and coalesce(p2.market_name, '') <> ''
                 order by p2.created_at desc
                 limit 1) as market_name,
               sum(b.plans)::bigint as model_plans,
               (select count(distinct ident)::bigint from (
                    select case
                             when coalesce(p3.owner, '') <> '' then 'o:' || p3.owner
                             else 'r:' || p3.reporter
                           end as ident
                      from plans p3
                     where lower(p3.model) = lower(b.model)
                    union all
                    select 'o:' || u.id::text as ident
                      from canta_users u
                     where lower(u.model) = lower(b.model)
                ) ids) as model_people
          from builds b
         group by b.brand, b.model
    )
    select b.brand, b.model, coalesce(m.market_name, ''), b.rom, b.rom_version,
           b.plans, b.people, m.model_plans, m.model_people
      from builds b
      join models m on m.brand = b.brand and m.model = b.model
     order by m.model_people desc, b.brand, b.model, b.rom_version desc, b.rom
$$;

revoke all on function public.plan_submit(jsonb) from public;
revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_get(bigint) from public;
revoke all on function public.plans_by_owner(text) from public;
revoke all on function public.plans_for_model(text, text, text, integer, integer) from public;
revoke all on function public.plan_catalog() from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_submit(jsonb) to anon;
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_get(bigint) to anon;
        grant execute on function public.plans_by_owner(text) to anon;
        grant execute on function public.plans_for_model(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_catalog() to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_submit(jsonb) to authenticated;
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_get(bigint) to authenticated;
        grant execute on function public.plans_by_owner(text) to authenticated;
        grant execute on function public.plans_for_model(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_catalog() to authenticated;
    end if;
end $$;
-- Marketing names for the models the community already talks about.
--
-- The catalog chips prefer the model's marketing name ("Redmi K70"); the fallback is the retail
-- model number the ROM reports ("23113RKC6C"), which is exactly what a visitor cannot read. The
-- `market_name` column is new, so every plan uploaded before it existed has none — and on
-- MIUI/HyperOS the retail number is the only thing those rows carry.
--
-- The names are already in the database, one hop away: comments have always stored the writer's
-- phone as *displayed* (`device_model`), and every comment is signed with the identity number
-- (`author_id`) whose `canta_users.model` is the retail number of the same phone. Pairing those two
-- turns "who wrote this comment" into "this retail number is called this":
--
--   canta_users.model (23113RKC6C)  <->  community_comments.device_model (Redmi K70)
--
-- Two uses:
--   1. a one-time backfill of `plans.market_name` where it is empty;
--   2. a live fallback inside `plan_catalog`, so a model with no named plan but with named
--      commenters still reads like a phone, not a part number.
--
-- Run after 20261119220000_device_catalog.sql (or use server/supabase/apply-all.sql).

-- The mapping view lives in `private`, out of the API's reach. The schema is not guaranteed to
-- exist on a deployment that never applied the telemetry migrations, so it is created here first.
create schema if not exists private;

/** Comment-derived "retail number -> marketing name" pairs, best pair decided by the caller. */
create or replace view private.model_names as
    select lower(u.model)                        as model,
           c.device_model                        as market_name,
           count(*)::bigint                      as votes
      from community_comments c
      join canta_users u on u.id::text = c.author_id
     where coalesce(c.device_model, '') <> ''
       and coalesce(u.model, '') <> ''
       and lower(c.device_model) <> lower(u.model)
     group by 1, 2;

comment on view private.model_names is
    'Pairs of retail model numbers and the names commenters'' phones showed; votes ranks them.';

-- Backfill once: every plan whose model has a known name gets it. Existing (non-empty) values stay
-- untouched, and re-running is harmless.
with best as (
    select distinct on (model) model, market_name
      from private.model_names
     order by model, votes desc
)
update plans p
   set market_name = best.market_name
  from best
 where coalesce(p.market_name, '') = ''
   and lower(p.model) = best.model;

/**
 * The catalog again, with one change: the model's display name now falls back to the names its
 * commenters' phones reported, not straight to the retail number. Shape is unchanged, so the
 * function is replaced in place.
 */
create or replace function public.plan_catalog() returns table (
    brand text, model text, market_name text, rom text, rom_version integer,
    plans bigint, people bigint, model_plans bigint, model_people bigint
) language sql stable security definer set search_path = public, private as $$
    with builds as (
        select coalesce(nullif(p.brand, ''), 'unknown') as brand,
               p.model,
               min(coalesce(p.codename, '')) as codename,
               p.rom,
               p.rom_version,
               count(*)::bigint as plans,
               count(distinct case
                        when coalesce(p.owner, '') <> '' then 'o:' || p.owner
                        else 'r:' || p.reporter
                      end)::bigint as people
          from plans p
         where coalesce(p.model, '') <> ''
         group by 1, 2, 4, 5
    ), codenames as (
        -- One codename per model string: the last fallback below needs it, the counts do not.
        select b.brand, b.model, min(nullif(b.codename, '')) as codename
          from builds b
         group by 1, 2
    ), models as (
        select b.brand,
               b.model,
               coalesce(
                   (select coalesce(p2.market_name, '')
                      from plans p2
                     where lower(p2.model) = lower(b.model)
                       and coalesce(p2.market_name, '') <> ''
                     order by p2.created_at desc
                     limit 1),
                   -- No plan on this model carries a name, but somebody who owns the phone left a
                   -- comment: their phone said what it is called.
                   (select m.market_name
                      from private.model_names m
                     where m.model = lower(b.model)
                     order by m.votes desc
                     limit 1),
                   -- Still nothing: lend it from another build of the same codename, i.e. the same
                   -- phone under the ROM's own name for it.
                   (select coalesce(p4.market_name, '')
                      from plans p4
                     where coalesce(cn.codename, '') <> ''
                       and lower(p4.codename) = lower(cn.codename)
                       and coalesce(p4.market_name, '') <> ''
                     order by p4.created_at desc
                     limit 1),
                   ''
               ) as market_name,
               sum(b.plans)::bigint as model_plans,
               (select count(distinct ident)::bigint from (
                    select case
                             when coalesce(p3.owner, '') <> '' then 'o:' || p3.owner
                             else 'r:' || p3.reporter
                           end as ident
                      from plans p3
                     where lower(p3.model) = lower(b.model)
                    union all
                    select 'o:' || u.id::text as ident
                      from canta_users u
                     where lower(u.model) = lower(b.model)
                ) ids) as model_people
          from builds b
          join codenames cn on cn.brand = b.brand and cn.model = b.model
         group by b.brand, b.model, cn.codename
    )
    select b.brand, b.model, coalesce(m.market_name, ''), b.rom, b.rom_version,
           b.plans, b.people, m.model_plans, m.model_people
      from builds b
      join models m on m.brand = b.brand and m.model = b.model
     order by m.model_people desc, b.brand, b.model, b.rom_version desc, b.rom
$$;

revoke all on function public.plan_catalog() from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_catalog() to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_catalog() to authenticated;
    end if;
end $$;

-- 20261120140000_comment_inbox.sql (inbox feed: hearts + paging)
-- The inbox: one feed of everything that happened to what this identity wrote.
--
-- Until now the inbox was one question with one answer — `comments_replies_to`, "did anybody answer
-- me?" — and the page asked for the whole answer at once, 200 rows in a single reply.
--
-- Three things were missing:
--
--   * hearts. A comment can be hearted (`comment_likes`) and a plan can be endorsed (`plan_votes`),
--     and the person who was hearted never learned about it: the count went up on a page they were
--     not looking at.
--   * comments on my plans. `comments_replies_to` joins on comments *of mine*, so somebody writing
--     under a plan I uploaded was invisible here.
--   * a shape that pages. Every reader below takes `limit`/`offset` and clamps both, so "load
--     everything" is not a request the backend can be given, and the app asks for one small page at
--     a time instead of 200 rows that freeze the list while they parse.
--
-- So this migration adds:
--
--   * `comment_likes.author_id`   who was hearted, so a heart can be reported back. Hearted before
--                                 this column existed means nobody can be told after the fact.
--   * `comments_by_targets`       what people wrote under the plans this identity uploaded.
--   * `hearts_for_owner`          my comments that were hearted, newest heart first, one row per
--                                 comment with the tally and the newest voter.
--   * `plan_hearts_for_owner`     my plans that were endorsed, same shape.
--   * `inbox_page`                the four sources merged into one feed, `p_per_source` rows each,
--                                 which is the "消息" list the page shows.
--   * `inbox_summary`             what the red dot counts: four numbers, no rows.
--   * `comments_by_author` / `comments_replies_to`  paged, with the title and the heart count.
--
-- The page size is the same number on both sides by intent: `private.inbox_page_max()` caps every
-- reader, and the app asks for a fifth of it per source, so a slow phone parses 40 short rows rather
-- than a 200-row answer.
--
-- Run after 20261120130000_plan_catalog_market_name_fallback.sql (or use server/supabase/apply-all.sql).

-- ---------------------------------------------------------------- who was hearted

-- The heart already had (comment_id, voter); the recipient is new, and only a heart that names one
-- can be reported to them. Empty on rows written before this column existed: "heart of an unknown
-- person" must not read as "heart of me".
alter table public.comment_likes add column if not exists author_id text not null default '';

-- The feed reads hearts by recipient, newest first, which is exactly this index.
create index if not exists comment_likes_author_idx
    on public.comment_likes (author_id, created_at desc);

/**
 * Taps the heart on [p_id]: [p_liked] true gives it, false takes it back, and both are safe to
 * repeat — the pair is the primary key, so tapping twice leaves one heart.
 *
 * Answers `{likes, liked}` with the count after the tap. Answers null when there is no comment to
 * heart (deleted while the page was open) or no identity to own the heart: a heart nobody owns is
 * one nobody can take back.
 *
 * The heart now records the comment's writer as well as the voter. The count does not need it — the
 * inbox does: without it there is no way to say "three people hearted your comment" to anybody.
 */
create or replace function public.comment_like(p_id bigint, p_voter text, p_liked boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    voter text := left(coalesce(p_voter, ''), 60);
    writer text;
    total bigint;
begin
    if p_id is null or voter = '' then
        return null;
    end if;
    select left(c.author_id, 60) into writer from community_comments c where c.id = p_id;
    if not found then
        return null;
    end if;

    if coalesce(p_liked, false) then
        insert into comment_likes (comment_id, voter, author_id) values (p_id, voter, writer)
        on conflict (comment_id, voter) do update set author_id = excluded.author_id;
    else
        delete from comment_likes l where l.comment_id = p_id and l.voter = voter;
    end if;

    select count(*) into total from comment_likes l where l.comment_id = p_id;
    return jsonb_build_object(
        'likes', total,
        'liked', exists (select 1 from comment_likes l
                          where l.comment_id = p_id and l.voter = voter)
    );
end;
$$;

-- ---------------------------------------------------------------- page size

/** The most rows any inbox reader will hand out in one call. */
create or replace function private.inbox_page_max() returns int language sql immutable set search_path = ''
as $$ select 50 $$;

/**
 * A caller's `limit`, clamped: 1..50, and 20 when it was not given.
 *
 * Every reader below goes through this, which is what keeps "give me everything" from being a
 * possible request.
 */
create or replace function private.inbox_limit(p_limit integer) returns int language sql immutable set search_path = ''
as $$ select greatest(1, least(coalesce(p_limit, 20), private.inbox_page_max())) $$;

/** A caller's `offset`, clamped at 0 and at a depth no page ever reaches. */
create or replace function private.inbox_offset(p_offset integer) returns int language sql immutable set search_path = ''
as $$ select greatest(0, least(coalesce(p_offset, 0), 10000)) $$;

-- ---------------------------------------------------------------- plans I uploaded

/**
 * What people wrote under the plans [p_owner] uploaded, newest first — answers included, because an
 * answer under a comment on my plan is news about my plan.
 *
 * This is the half `comments_replies_to` cannot see: that reader joins on comments *of mine*, and a
 * comment of somebody else on my plan is a different event from a comment of mine anywhere.
 *
 * The uploader is matched on `plans.owner`, the identity number the upload was signed with; a plan
 * from before those numbers existed is matched on the reporter field it was signed with instead.
 * Comments by [p_owner] itself are left out: "you commented your own plan" is not news.
 */
create or replace function public.comments_by_targets(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    id bigint, parent_id bigint, parent_body text, kind text, target text, title text,
    author text, author_id text, body text, created_at timestamptz, likes bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.parent_id,
           coalesce(pc.body, '') as parent_body,
           c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           coalesce(nullif(u.name, ''), c.author) as author,
           c.author_id, c.body, c.created_at,
           (select count(*) from comment_likes l where l.comment_id = c.id)::bigint
      from community_comments c
      left join community_comments pc on pc.id = c.parent_id
      left join canta_users u on u.id::text = c.author_id
     where c.kind = 'plan'
       and c.target in (
            select p.id::text from plans p
             where coalesce(p_owner, '') <> ''
               and (p.owner = p_owner
                    or (p.owner = '' and p.reporter in (coalesce(p_owner, ''),
                                                        coalesce(p_token, ''),
                                                        left(coalesce(p_token, ''), 16))))
       )
       and c.author_id not in (coalesce(p_owner, ''), coalesce(p_token, ''))
     order by c.created_at desc, c.id desc
     limit private.inbox_limit(p_limit)
    offset private.inbox_offset(p_offset)
$$;

-- ---------------------------------------------------------------- hearts on my comments

/**
 * Comments [p_owner] wrote that were hearted, newest heart first, one row per comment.
 *
 * One row per comment, not per heart: ten people hearting the same comment is one line saying ten,
 * which is what that sentence means and what keeps the list from filling with the same comment ten
 * times over. [likes] is the tally, [last_heart_at] and [last_voter] are the news.
 *
 * [last_voter_name] is the name that voter uses today, so a line reads "小张 等 3 人赞了你的评论"
 * instead of naming an identity number.
 */
create or replace function public.hearts_for_owner(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    comment_id bigint, kind text, target text, title text, body text,
    likes bigint, last_heart_at timestamptz, last_voter text, last_voter_name text
) language sql stable security definer set search_path = public as $$
    with grouped as (
        select c.id, c.kind, c.target, c.body,
               count(l.comment_id)::bigint as likes,
               max(l.created_at) as last_heart_at,
               -- The newest voter, which is who the row names: the count is the tally, this is the
               -- face. Taken in the same grouping rather than in a subquery, because an aggregate
               -- cannot be read from inside a correlated subquery.
               (array_agg(l.voter order by l.created_at desc))[1] as last_voter
          from community_comments c
          join comment_likes l on l.comment_id = c.id
         where (c.author_id in (coalesce(p_owner, ''), coalesce(p_token, ''), left(coalesce(p_token, ''), 16))
                or (c.author_id = ''
                    and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))))
           and l.voter not in (coalesce(p_owner, ''), coalesce(p_token, ''))
         group by c.id, c.kind, c.target, c.body
         order by max(l.created_at) desc, c.id desc
         limit private.inbox_limit(p_limit)
        offset private.inbox_offset(p_offset)
    )
    select g.id, g.kind, g.target,
           coalesce((select left(p.title, 120) from plans p
                      where g.kind = 'plan' and p.id::text = g.target), '') as title,
           g.body, g.likes, g.last_heart_at, g.last_voter,
           coalesce((select nullif(u.name, '') from canta_users u
                      where u.id::text = g.last_voter), '') as last_voter_name
      from grouped g
     order by g.last_heart_at desc, g.id desc
$$;

-- ---------------------------------------------------------------- hearts on my plans

/**
 * Plans [p_owner] uploaded that were endorsed, newest endorsement first — the same piece of news
 * as a hearted comment, for the other thing this identity publishes.
 */
create or replace function public.plan_hearts_for_owner(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    plan_id bigint, title text, body text,
    likes bigint, last_heart_at timestamptz, last_voter text, last_voter_name text
) language sql stable security definer set search_path = public as $$
    with grouped as (
        select p.id, left(p.title, 120) as title, left(coalesce(p.note, ''), 200) as note,
               count(v.voter)::bigint as likes,
               max(v.created_at) as last_heart_at,
               (array_agg(v.voter order by v.created_at desc))[1] as last_voter
          from plans p
          join plan_votes v on v.plan_id = p.id
         where coalesce(p_owner, '') <> ''
           and (p.owner = p_owner
                or (p.owner = '' and p.reporter in (coalesce(p_owner, ''),
                                                    coalesce(p_token, ''),
                                                    left(coalesce(p_token, ''), 16))))
           and v.voter not in (coalesce(p_owner, ''), coalesce(p_token, ''))
         group by p.id, p.title, p.note
         order by max(v.created_at) desc, p.id desc
         limit private.inbox_limit(p_limit)
        offset private.inbox_offset(p_offset)
    )
    select g.id, g.title, g.note, g.likes, g.last_heart_at, g.last_voter,
           coalesce((select nullif(u.name, '') from canta_users u
                      where u.id::text = g.last_voter), '') as last_voter_name
      from grouped g
     order by g.last_heart_at desc, g.id desc
$$;

-- ---------------------------------------------------------------- the two list readers, paged

-- Both readers change their return shape (`title`, `likes`), and a return type cannot be replaced in
-- place: drop the old signatures first, so no caller is left on the 200-row version.
drop function if exists public.comments_by_author(text);
drop function if exists public.comments_by_author(text, text);
drop function if exists public.comments_replies_to(text);
drop function if exists public.comments_replies_to(text, text);

/**
 * What one identity wrote, newest first: the comments it started *and* the replies it left, each
 * with the plan or app it belongs to and how many hearts it carries.
 */
create or replace function public.comments_by_author(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint, likes bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint,
           (select count(*) from comment_likes l where l.comment_id = c.id)::bigint
      from community_comments c
     where c.author_id in (coalesce(p_owner, ''), coalesce(p_token, ''), left(coalesce(p_token, ''), 16))
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
     order by c.created_at desc, c.id desc
     limit private.inbox_limit(p_limit)
    offset private.inbox_offset(p_offset)
$$;

/**
 * The replies other people left under [p_owner]'s comments, newest first — the "somebody answered
 * me" source of the feed, paged like the reader above.
 */
create or replace function public.comments_replies_to(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    id bigint, parent_id bigint, kind text, target text, title text,
    author text, body text, created_at timestamptz, parent_body text
) language sql stable security definer set search_path = public as $$
    select r.id, c.id,
           r.kind, r.target,
           coalesce((select left(p.title, 120) from plans p
                      where r.kind = 'plan' and p.id::text = r.target), '') as title,
           coalesce(nullif(ru.name, ''), r.author) as author,
           r.body, r.created_at, c.body
      from community_comments r
      join community_comments c on c.id = r.parent_id
      left join canta_users ru on ru.id::text = r.author_id
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
     order by r.created_at desc, r.id desc
     limit private.inbox_limit(p_limit)
    offset private.inbox_offset(p_offset)
$$;

-- ---------------------------------------------------------------- the feed

/**
 * The four sources merged into one list, newest first: what the "消息" tab shows.
 *
 * [p_per_source] rows are taken from each source at [p_offset], so the list grows by asking for the
 * next offset rather than by asking for "more" and hoping: page N of a source is the same rows
 * whatever else happened in between, and a source that runs out simply stops contributing. Merging
 * in SQL means one request per scroll instead of four, and the order is the server's.
 *
 * The `src` column says which source a row came from, and is part of the sort: it is what tells the
 * page whether to draw a reply, a heart on a comment or a heart on a plan, and it keeps the order
 * total when two events share a timestamp.
 *
 * Rows are ≤ 4 × `private.inbox_page_max()` by construction, and 40 in practice.
 */
create or replace function public.inbox_page(
    p_owner text, p_token text default '', p_per_source integer default 10, p_offset integer default 0
) returns table (
    src text, src_id bigint, kind text, target text, title text,
    body text, parent_body text, actor text, actor_name text,
    likes bigint, created_at timestamptz
) language sql stable security definer set search_path = public as $$
    with feed as (
        select 'reply'::text as src, r.id as src_id, r.kind, r.target, r.title,
               r.body, r.parent_body, r.author as actor, r.author as actor_name,
               0::bigint as likes, r.created_at
          from public.comments_replies_to(p_owner, p_token, p_per_source, p_offset) r
        union all
        select 'plan_comment', c.id, c.kind, c.target, c.title,
               c.body, c.parent_body, c.author, c.author,
               c.likes, c.created_at
          from public.comments_by_targets(p_owner, p_token, p_per_source, p_offset) c
        union all
        select 'comment_heart', h.comment_id, h.kind, h.target, h.title,
               h.body, ''::text, h.last_voter, h.last_voter_name,
               h.likes, h.last_heart_at
          from public.hearts_for_owner(p_owner, p_token, p_per_source, p_offset) h
        union all
        select 'plan_heart', ph.plan_id, 'plan'::text, ph.plan_id::text, ph.title,
               ph.body, ''::text, ph.last_voter, ph.last_voter_name,
               ph.likes, ph.last_heart_at
          from public.plan_hearts_for_owner(p_owner, p_token, p_per_source, p_offset) ph
    )
    select f.src, f.src_id, f.kind, f.target, f.title,
           f.body, f.parent_body, f.actor, f.actor_name, f.likes, f.created_at
      from feed f
     order by f.created_at desc, f.src desc, f.src_id desc
$$;

-- ---------------------------------------------------------------- the red dot

/**
 * What is waiting for [p_owner], as four numbers and no rows: the counts the red dot adds up.
 *
 * The dot used to be "replies newer than the last id I opened", which was the whole feed when
 * replies were the whole feed. Now hearts, comments on my plans and endorsements of my plans are
 * feed too, so the dot is the sum of the four — asked of the server, which is the only place that
 * knows, and cheap because each one is an indexed count rather than a page of rows.
 *
 * [newest_comment_id] is the largest comment id among the comment-shaped events, so the page can
 * still mark "newer than the last one I opened" on individual rows.
 */
create or replace function public.inbox_summary(p_owner text, p_token text default '')
returns jsonb language sql stable security definer set search_path = public as $$
    with me as (
        select coalesce(p_owner, '') as owner, coalesce(p_token, '') as token
    ),
    replies as (
        select count(*)::bigint as n, coalesce(max(r.id), 0) as newest
          from community_comments r
          join community_comments c on c.id = r.parent_id
          cross join me m
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and r.author_id <> c.author_id
           and r.author_id not in (m.owner, m.token)
    ),
    on_plans as (
        select count(*)::bigint as n, coalesce(max(c.id), 0) as newest
          from community_comments c
          cross join me m
         where c.kind = 'plan'
           and m.owner <> ''
           and c.target in (
                select p.id::text from plans p
                 where p.owner = m.owner
                    or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16)))
           )
           and c.author_id not in (m.owner, m.token)
    ),
    comment_hearts as (
        select count(*)::bigint as n
          from community_comments c
          cross join me m
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and exists (select 1 from comment_likes l
                        where l.comment_id = c.id and l.voter not in (m.owner, m.token))
    ),
    plan_hearts as (
        select count(*)::bigint as n
          from plans p
          cross join me m
         where m.owner <> ''
           and (p.owner = m.owner
                or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16))))
           and exists (select 1 from plan_votes v
                        where v.plan_id = p.id and v.voter not in (m.owner, m.token))
    )
    select jsonb_build_object(
        'replies', (select n from replies),
        'plan_comments', (select n from on_plans),
        'comment_hearts', (select n from comment_hearts),
        'plan_hearts', (select n from plan_hearts),
        'newest_comment_id', greatest(
            (select newest from replies),
            (select newest from on_plans)
        )
    )
$$;

-- ---------------------------------------------------------------- grants

revoke all on function public.comment_like(bigint, text, boolean) from public;
revoke all on function public.comments_by_targets(text, text, integer, integer) from public;
revoke all on function public.hearts_for_owner(text, text, integer, integer) from public;
revoke all on function public.plan_hearts_for_owner(text, text, integer, integer) from public;
revoke all on function public.inbox_page(text, text, integer, integer) from public;
revoke all on function public.inbox_summary(text, text) from public;
revoke all on function public.comments_by_author(text, text, integer, integer) from public;
revoke all on function public.comments_replies_to(text, text, integer, integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comment_like(bigint, text, boolean) to anon;
        grant execute on function public.comments_by_targets(text, text, integer, integer) to anon;
        grant execute on function public.hearts_for_owner(text, text, integer, integer) to anon;
        grant execute on function public.plan_hearts_for_owner(text, text, integer, integer) to anon;
        grant execute on function public.inbox_page(text, text, integer, integer) to anon;
        grant execute on function public.inbox_summary(text, text) to anon;
        grant execute on function public.comments_by_author(text, text, integer, integer) to anon;
        grant execute on function public.comments_replies_to(text, text, integer, integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comment_like(bigint, text, boolean) to authenticated;
        grant execute on function public.comments_by_targets(text, text, integer, integer) to authenticated;
        grant execute on function public.hearts_for_owner(text, text, integer, integer) to authenticated;
        grant execute on function public.plan_hearts_for_owner(text, text, integer, integer) to authenticated;
        grant execute on function public.inbox_page(text, text, integer, integer) to authenticated;
        grant execute on function public.inbox_summary(text, text) to authenticated;
        grant execute on function public.comments_by_author(text, text, integer, integer) to authenticated;
        grant execute on function public.comments_replies_to(text, text, integer, integer) to authenticated;
    end if;
end $$;


-- ================================================================ 描述修正
-- Community-corrected descriptions: the bloat list's one line about what an app is, rewritten by
-- the people who actually run it, and voted on until it can stand in for the published line.
-- Same content as migrations/20261120150000_description_fixes.sql.

create table if not exists public.description_fixes (
    id         bigserial primary key,
    pkg        text not null,
    body       text not null,
    note       text not null default '',
    author     text not null default '',
    author_id  text not null default '',
    applied    boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists description_fixes_pkg_idx
    on public.description_fixes (pkg, applied desc, created_at desc);

create table if not exists public.description_fix_votes (
    fix_id     bigint not null references public.description_fixes (id) on delete cascade,
    voter      text not null,
    agree      boolean not null,
    created_at timestamptz not null default now(),
    primary key (fix_id, voter)
);

create index if not exists description_fix_votes_fix_idx on public.description_fix_votes (fix_id);

alter table public.description_fixes enable row level security;
alter table public.description_fix_votes enable row level security;

create or replace function private.description_fix_votes_needed() returns int
language sql immutable set search_path = ''
as $$ select 50 $$;

create or replace function private.description_fix_share_needed() returns numeric
language sql immutable set search_path = ''
as $$ select 0.80::numeric $$;

create or replace function private.description_fix_settle(p_pkg text)
returns void language plpgsql security definer set search_path = public as $$
declare
    winner bigint;
begin
    select t.fix_id into winner
    from (
        select f.id as fix_id,
               f.created_at,
               count(*) filter (where v.agree) as agrees,
               count(*) filter (where not v.agree) as disagrees
        from description_fixes f
        left join description_fix_votes v on v.fix_id = f.id
        where f.pkg = p_pkg
        group by f.id, f.created_at
    ) t
    where t.agrees >= private.description_fix_votes_needed()
      and t.agrees >= private.description_fix_share_needed() * greatest(t.agrees + t.disagrees, 1)
    order by t.agrees desc, t.created_at asc
    limit 1;

    update description_fixes
       set applied = (id = coalesce(winner, -1))
     where pkg = p_pkg
       and applied <> (id = coalesce(winner, -1));
end;
$$;

create or replace function public.description_fix_add(
    p_pkg text,
    p_body text,
    p_note text default '',
    p_author text default '',
    p_author_id text default ''
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
    pkg_text text := left(btrim(coalesce(p_pkg, '')), 200);
    body_text text := left(btrim(coalesce(p_body, '')), 4000);
    note_text text := left(btrim(coalesce(p_note, '')), 300);
    author_text text := left(btrim(coalesce(p_author, '')), 60);
    author_id_text text := left(btrim(coalesce(p_author_id, '')), 60);
    existing bigint;
    new_id bigint;
begin
    if pkg_text = '' or body_text = '' then
        return null;
    end if;

    if author_id_text <> '' then
        select f.id into existing
        from description_fixes f
        where f.pkg = pkg_text
          and f.author_id = author_id_text
          and not f.applied
        order by f.created_at desc
        limit 1;
    end if;

    if existing is not null then
        update description_fixes
           set body = body_text,
               note = note_text,
               author = author_text,
               updated_at = now()
         where id = existing;
        perform private.description_fix_settle(pkg_text);
        return jsonb_build_object('id', existing);
    end if;

    insert into description_fixes (pkg, body, note, author, author_id)
    values (pkg_text, body_text, note_text, author_text, author_id_text)
    returning id into new_id;

    perform private.description_fix_settle(pkg_text);
    return jsonb_build_object('id', new_id);
end;
$$;

create or replace function public.description_fix_vote(p_id bigint, p_voter text, p_agree boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    voter_text text := left(btrim(coalesce(p_voter, '')), 60);
    fix_pkg text;
    yes_count bigint;
    no_count bigint;
    is_applied boolean;
begin
    if p_id is null or voter_text = '' then
        return null;
    end if;

    select f.pkg into fix_pkg from description_fixes f where f.id = p_id;
    if not found then
        return null;
    end if;

    insert into description_fix_votes (fix_id, voter, agree)
    values (p_id, voter_text, coalesce(p_agree, true))
    on conflict (fix_id, voter) do update
        set agree = excluded.agree,
            created_at = now();

    perform private.description_fix_settle(fix_pkg);

    select count(*) filter (where agree), count(*) filter (where not agree)
      into yes_count, no_count
      from description_fix_votes
     where fix_id = p_id;

    select applied into is_applied from description_fixes where id = p_id;

    return jsonb_build_object(
        'agrees', yes_count,
        'disagrees', no_count,
        'applied', coalesce(is_applied, false)
    );
end;
$$;

create or replace function public.description_fixes_for(p_pkg text, p_voter text default '')
returns jsonb language sql stable security definer set search_path = public as $$
    select coalesce(jsonb_agg(
        jsonb_build_object(
            'id', r.id,
            'body', r.body,
            'note', r.note,
            'author', r.author,
            'author_id', r.author_id,
            'created_at', r.created_at,
            'applied', r.applied,
            'agrees', r.agrees,
            'disagrees', r.disagrees,
            'mine', r.mine,
            'needed', private.description_fix_votes_needed(),
            'share', private.description_fix_share_needed()
        )
        order by r.applied desc, r.agrees desc, r.created_at desc
    ), '[]'::jsonb)
    from (
        select f.id, f.body, f.note, f.author, f.author_id, f.created_at, f.applied,
               coalesce(v.agrees, 0) as agrees,
               coalesce(v.disagrees, 0) as disagrees,
               v.mine
        from description_fixes f
        left join lateral (
            select count(*) filter (where vv.agree) as agrees,
                   count(*) filter (where not vv.agree) as disagrees,
                   (array_agg(vv.agree) filter (
                       where vv.voter = left(coalesce(p_voter, ''), 60)
                   ))[1] as mine
            from description_fix_votes vv
            where vv.fix_id = f.id
        ) v on true
        where f.pkg = left(coalesce(p_pkg, ''), 200)
    ) r
$$;

create or replace function public.description_fix_current(p_pkg text)
returns jsonb language sql stable security definer set search_path = public as $$
    select jsonb_build_object(
        'id', f.id,
        'body', f.body,
        'note', f.note,
        'author', f.author,
        'created_at', f.created_at,
        'agrees', (select count(*) from description_fix_votes v
                    where v.fix_id = f.id and v.agree),
        'disagrees', (select count(*) from description_fix_votes v
                       where v.fix_id = f.id and not v.agree)
    )
    from description_fixes f
    where f.pkg = left(coalesce(p_pkg, ''), 200)
      and f.applied
    order by f.created_at desc
    limit 1
$$;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.description_fix_add(text, text, text, text, text) to anon;
        grant execute on function public.description_fix_vote(bigint, text, boolean) to anon;
        grant execute on function public.description_fixes_for(text, text) to anon;
        grant execute on function public.description_fix_current(text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.description_fix_add(text, text, text, text, text) to authenticated;
        grant execute on function public.description_fix_vote(bigint, text, boolean) to authenticated;
        grant execute on function public.description_fixes_for(text, text) to authenticated;
        grant execute on function public.description_fix_current(text) to authenticated;
    end if;
end $$;


-- ================================================================ 红点的已读游标
-- The red dot counts what arrived since the inbox was last opened, not everything that ever
-- happened: the count takes a cursor the backend itself stamped, and hands the next one back.
-- Same content as migrations/20261120160000_inbox_seen_cursor.sql.

-- The signature changes, and `create or replace` cannot add an argument: the old two-argument
-- function has to go, or both would exist and PostgREST would keep resolving the old one.
drop function if exists public.inbox_summary(text, text);

/**
 * What is waiting for [p_owner] since [p_seen_at], as four numbers and no rows.
 *
 * Each count is "rows newer than the cursor", which is what the red dot adds up. [checked_at] comes
 * back with them: the instant this answer was taken at, which the page stores and sends as the next
 * call's [p_seen_at]. That round trip is the whole read cursor — nothing is stored server side, and
 * nothing depends on the phone's clock.
 *
 * [newest_comment_id] stays the largest comment id among the comment-shaped events, unfiltered by
 * the cursor: the list still marks individual rows as "newer than the last one I opened".
 */
create or replace function public.inbox_summary(
    p_owner text,
    p_token text default '',
    p_seen_at text default ''
)
returns jsonb language sql stable security definer set search_path = public as $$
    with me as (
        select coalesce(p_owner, '') as owner, coalesce(p_token, '') as token
    ),
    mark as (
        -- The cursor, as an instant. A malformed one (a stored string from an older build, say)
        -- falls back to "everything" rather than failing the count: a red dot that cannot be
        -- computed is worse than one that is too eager.
        select case
                   when coalesce(p_seen_at, '') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                       then left(coalesce(p_seen_at, ''), 40)::timestamptz
               end as ts
    ),
    replies as (
        select count(*)::bigint as n, coalesce(max(r.id), 0) as newest
          from community_comments r
          join community_comments c on c.id = r.parent_id
          cross join me m
          cross join mark
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and r.author_id <> c.author_id
           and r.author_id not in (m.owner, m.token)
           and (mark.ts is null or r.created_at > mark.ts)
    ),
    on_plans as (
        select count(*)::bigint as n, coalesce(max(c.id), 0) as newest
          from community_comments c
          cross join me m
          cross join mark
         where c.kind = 'plan'
           and m.owner <> ''
           and c.target in (
                select p.id::text from plans p
                 where p.owner = m.owner
                    or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16)))
           )
           and c.author_id not in (m.owner, m.token)
           and (mark.ts is null or c.created_at > mark.ts)
    ),
    comment_hearts as (
        select count(*)::bigint as n
          from community_comments c
          cross join me m
          cross join mark
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and exists (select 1 from comment_likes l
                        where l.comment_id = c.id and l.voter not in (m.owner, m.token)
                          and (mark.ts is null or l.created_at > mark.ts))
    ),
    plan_hearts as (
        select count(*)::bigint as n
          from plans p
          cross join me m
          cross join mark
         where m.owner <> ''
           and (p.owner = m.owner
                or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16))))
           and exists (select 1 from plan_votes v
                        where v.plan_id = p.id and v.voter not in (m.owner, m.token)
                          and (mark.ts is null or v.created_at > mark.ts))
    )
    select jsonb_build_object(
        'replies', (select n from replies),
        'plan_comments', (select n from on_plans),
        'comment_hearts', (select n from comment_hearts),
        'plan_hearts', (select n from plan_hearts),
        'newest_comment_id', greatest(
            (select newest from replies),
            (select newest from on_plans)
        ),
        -- Stamped here, in UTC, so the string the app stores compares and parses the same way
        -- whatever time zone the session happens to be in.
        'checked_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    )
$$;

revoke all on function public.inbox_summary(text, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.inbox_summary(text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.inbox_summary(text, text, text) to authenticated;
    end if;
end $$;

-- The function the app calls changed shape, and a cached schema would answer "no such function" —
-- which the app reads as an older deployment and silently falls back on. Reload it here.
notify pgrst, 'reload schema';

-- 20261120170000_plan_sdk: the plan rows now carry `sdk`, the Android level the uploader ran, so
-- the detail header can name that phone start to finish instead of borrowing the reader's release.
-- A return type cannot be replaced in place: each reader is dropped and rebuilt with the new column.

drop function if exists public.plans_for(text, text, text, integer, integer);
drop function if exists public.plan_get(bigint);
drop function if exists public.plans_by_owner(text);
drop function if exists public.plans_for_model(text, text, text, integer, integer);
drop function if exists public.plans_all(integer);

create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer, sdk integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version, p.sdk
    from plans p
    left join canta_users u on u.id::text = p.owner
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

create or replace function public.plan_get(p_id bigint) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer, sdk integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version, p.sdk
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.id = p_id
     limit 1
$$;

create or replace function public.plans_by_owner(p_owner text) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer, sdk integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version, p.sdk
      from plans p
      left join canta_users u on u.id::text = p.owner
     where coalesce(p_owner, '') <> ''
       and p.owner = p_owner
     order by p.created_at desc
     limit 200
$$;

create or replace function public.plans_for_model(
    p_model text, p_brand text default '', p_rom text default '', p_rom_version integer default 0,
    p_limit integer default 100
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer, sdk integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version, p.sdk
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.reboot_verified
       and coalesce(p_model, '') <> ''
       and lower(p.model) = lower(p_model)
       and (coalesce(p_brand, '') = '' or lower(p.brand) = lower(p_brand))
       and (
             coalesce(p_rom, '') = ''
             or (p.rom = p_rom and (coalesce(p_rom_version, 0) = 0 or p.rom_version = p_rom_version))
           )
     order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
     limit greatest(1, least(coalesce(p_limit, 100), 200))
$$;

create or replace function public.plans_all(p_limit integer default 200)
returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer, sdk integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version, p.sdk
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.reboot_verified
     order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
     limit greatest(1, least(coalesce(p_limit, 200), 200))
$$;

revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_get(bigint) from public;
revoke all on function public.plans_by_owner(text) from public;
revoke all on function public.plans_for_model(text, text, text, integer, integer) from public;
revoke all on function public.plans_all(integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_get(bigint) to anon;
        grant execute on function public.plans_by_owner(text) to anon;
        grant execute on function public.plans_for_model(text, text, text, integer, integer) to anon;
        grant execute on function public.plans_all(integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_get(bigint) to authenticated;
        grant execute on function public.plans_by_owner(text) to authenticated;
        grant execute on function public.plans_for_model(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plans_all(integer) to authenticated;
    end if;
end $$;

notify pgrst, 'reload schema';
