-- A plan shows the name its uploader uses now, not just the identity number.
--
-- The plan list draws the uploader next to a letter avatar (the first character of the name), the
-- same way comments and the settings screen do. Without this, every plan card would read "#10000",
-- which is a number, not a person.
--
-- `plans_for` therefore also returns `owner_name`: the name the uploader picked in Settings, empty
-- when they never picked one. The app falls back to "#<owner>" in that case, so an older deployment
-- or an unnamed uploader still renders something readable.
--
-- Run after 20261119170000_comment_author_names.sql (or use server/supabase/apply-all.sql).

-- The shape changes (owner_name is new), and a return type cannot be replaced in place.
drop function if exists public.plans_for(text, text, text, integer, integer);

/**
 * Verified plans for one device, most liked first, each with the name its uploader uses today.
 *
 * Matching is still exact on model, codename, ROM and ROM version: a plan for another build is
 * worthless. Test plans sort after verified ones, as before.
 */
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
      and (p.codename = '' or lower(p.codename) = lower(p_codename))
      and p.rom = p_rom
      and p.rom_version = p_rom_version
    order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
    limit greatest(1, least(p_limit, 100))
$$;

revoke all on function public.plans_for(text, text, text, integer, integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
    end if;
end $$;
