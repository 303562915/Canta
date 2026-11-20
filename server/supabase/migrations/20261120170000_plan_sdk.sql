-- The plan row carries the Android level its reboot check passed on.
--
-- `plan_submit` has always stored `sdk`, but no read ever returned it: the plan detail header could
-- name only the model and the ROM ("Redmi K70 · HyperOS 2"), and it filled the rest of the device
-- line with the *reader's* release — a number belonging to another phone, printed under somebody
-- else's verdict. Returning the column makes the line describe the uploader's device end to end.
--
-- A return type cannot be replaced in place, so every function that answers with a plan row is
-- dropped and rebuilt with the same columns plus `sdk`, the way 20261119220000 did for the device
-- columns. Nothing changes about what a plan is matched against.
--
-- Run after 20261120160000_plans_all.sql (or use server/supabase/apply-all.sql).

drop function if exists public.plans_for(text, text, text, integer, integer);
drop function if exists public.plan_get(bigint);
drop function if exists public.plans_by_owner(text);
drop function if exists public.plans_for_model(text, text, text, integer, integer);
drop function if exists public.plans_all(integer);

/** Verified plans for one device, most liked first, with the build each plan was made on. */
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

/** One plan by id, for the pages that open a plan from a comment, a share code or another model. */
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

/** Every plan one identity uploaded, whatever device it was matched to, newest first. */
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

/** The plans of another model — the browser behind the model chips. */
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

/** Every verified plan, whatever the phone — the widest scope of the ranking. */
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

-- A cached schema would answer "no such function" for the old signature, which the app reads as an
-- older deployment. Reload it here.
notify pgrst, 'reload schema';