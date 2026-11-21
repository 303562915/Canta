-- 社区推荐的通过门槛：50 票 → 45 票。
--
-- 五十票在冷启动阶段几乎等不到：一条推荐要凑满五十个投票的人，页面上就永远只有提交者自己
-- 那一条。45 票仍然要八成认同（36 票赞成），所以"少数人硬推"照样过不了，变的只是等多久。
-- 旧的 `20261121120000_recommend_suggestions.sql` 注释写着"40 of 50"，历史迁移不改，这里覆盖它。
--
-- 改完要把已经够线的旧条目重新裁决一次：阈值降了，`applied` 却只在有人投票时才重算，那些
-- 45–49 票的条目否则会一直挂在队列里等一张永远不会来的票。
--
-- Run after 20261121140000_inbox_seen_by_kind.sql (or use server/supabase/apply-all.sql).

create or replace function private.recommend_votes_needed() returns int
language sql immutable set search_path = ''
as $$ select 45 $$;

do $$
declare
    entry record;
begin
    for entry in
        select distinct url from public.recommend_suggestions where not applied
    loop
        perform private.recommend_settle(entry.url);
    end loop;
end $$;