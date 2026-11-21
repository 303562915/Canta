-- 后端到底活着没有。
--
-- 换后端只是改 base URL 和 key，改错了客户端看到的只有一句"网络错误"：地址不通、key 不对、
-- 迁移没跑，三种原因长一个样。这个 RPC 一次回答三件事——函数本身跑得起来（`ok`）、库的时钟
-- （`now`）、以及社区方案那张表读得到几行（`plans`）。表被清空或者迁移只跑了一半，第三个数字
-- 会直接掉到 0。
--
-- 只读，不写任何东西。`security definer` 是为了绕开 `plans` 上的 RLS：健康检查不该要求调用者
-- 有任何身份，`anon` 也必须能问。
--
-- Run after 20261121120000_recommend_suggestions.sql (or use server/supabase/apply-all.sql).

create or replace function public.healthz() returns jsonb
language sql stable security definer set search_path = public as $$
    select jsonb_build_object(
        'ok', true,
        'now', now(),
        'plans', (select count(*) from public.plans)
    )
$$;

revoke all on function public.healthz() from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.healthz() to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.healthz() to authenticated;
    end if;
end $$;

notify pgrst, 'reload schema';