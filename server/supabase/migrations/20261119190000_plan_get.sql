-- One plan by id, for the pages that open a plan from a comment or a share code.
--
-- `plans_for` only ever answers for the caller's own model, codename and ROM version, which is the
-- right filter for the list but the wrong one for a link: a comment written before an OS update, or
-- on a plan another model uploaded, still has to open. This adds the single-row read the detail page
-- falls back to when the plan is not in its own list.
--
-- The row carries the same columns as `plans_for`, including `owner_name`, so the detail page reads
-- both calls through one parser. A plan that is not reboot-verified is still returned: the detail
-- page is what says whether it is a test plan.
--
-- Run after 20261119180000_plan_author_names.sql (or use server/supabase/apply-all.sql).

create or replace function public.plan_get(p_id bigint) returns table (
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
     where p.id = p_id
     limit 1
$$;

revoke all on function public.plan_get(bigint) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_get(bigint) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_get(bigint) to authenticated;
    end if;
end $$;
