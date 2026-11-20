-- 一份方案到底在哪些机器上验证过。
--
-- 方案页现在只说上传者那一台，读者看到的回答是"在别人的手机上通过了"，而不是
-- "在红米 K70 和 iQOO 12 上都通过了"。同一组包在不同机型上过重启验证的记录是现成的，
-- 只是没人把它们按包集合归到一起。
--
-- 归并的键是包的集合，不是数组顺序：同一份方案两个人上传，勾选顺序可能不同，
-- 那是同一件事。只有通过重启验证（is_test = false）的才计数——上传就算数的机型列表
-- 只是在报"谁传过"，不是"谁的手机没坏"。
--
-- Run after 20261120180000_plan_set_note.sql (or use server/supabase/apply-all.sql).

create or replace function public.plan_device_coverage(p_packages text[], p_limit integer default 5)
returns table (
    brand text,
    model text,
    market_name text,
    rom text,
    rom_version integer,
    sdk integer,
    verified bigint
)
language sql stable security definer set search_path = public as $$
    with mine as (
        -- The set asked about, sorted so the comparison below is about content, not order.
        select array_agg(distinct x order by x) as pkgs from unnest(p_packages) x
    )
    select p.brand, p.model, p.market_name, p.rom, p.rom_version, p.sdk, count(*) as verified
      from plans p, mine
     where p.is_test = false
       and p.packages is not null
       and (select array_agg(distinct y order by y) from unnest(p.packages) y) = mine.pkgs
     group by p.brand, p.model, p.market_name, p.rom, p.rom_version, p.sdk
     order by verified desc, p.model asc
     limit greatest(1, least(coalesce(p_limit, 5), 20));
$$;

revoke all on function public.plan_device_coverage(text[], integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_device_coverage(text[], integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_device_coverage(text[], integer) to authenticated;
    end if;
end $$;