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
