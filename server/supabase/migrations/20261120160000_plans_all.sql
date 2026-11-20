-- Every verified plan, whatever the phone.
--
-- `plans_for` matches one build exactly and `plans_for_model` one model; both can answer "nobody
-- uploaded for this phone yet", which on a young community is most phones. This function is the
-- door behind the "全部机型" scope: the ranking of what the community removes most, before there
-- is a phone to match it. It only reads rows that already passed the reboot check.

create or replace function public.plans_all(p_limit integer default 200)
returns table (
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
     order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
     limit greatest(1, least(coalesce(p_limit, 200), 200))
$$;

revoke all on function public.plans_all(integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_all(integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_all(integer) to authenticated;
    end if;
end $$;
