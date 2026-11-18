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
