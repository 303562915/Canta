-- The plans one identity uploaded, for the "manage my plans" list.
--
-- `plans_for` answers for one model and ROM version, which is what the community list wants and the
-- opposite of what management wants: after an OS update, or from a phone that has since changed,
-- the plan no longer matches `plans_for` and would silently disappear from the list that exists to
-- delete it. This returns the owner's own plans regardless of device.
--
-- The shape matches `plans_for` exactly (including `owner_name`), so both read through one parser.
-- Deleting still goes through `plan_delete`, which needs the identity number *and* its token.
--
-- Run after 20261119220000_device_catalog.sql (or use server/supabase/apply-all.sql).

create or replace function public.plans_by_owner(p_owner text) returns table (
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
     where coalesce(p_owner, '') <> ''
       and p.owner = p_owner
     order by p.created_at desc
     limit 200
$$;

revoke all on function public.plans_by_owner(text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_by_owner(text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_by_owner(text) to authenticated;
    end if;
end $$;
