-- 清空社区的方案：所有人上传的方案，连同它们的赞、旧评论和新评论表里的方案评论，一次清掉。
--
-- 这不是结构变更，是一次一次性的数据清理：`plans` 里的每一行都会被删掉，`plan_votes`
-- 和 `plan_comments` 由外键 `on delete cascade` 跟着走；`community_comments` 里的方案评论没有
-- 指向 `plans` 的外键（它按 `kind`/`target` 认页面），所以要按 kind 单独删，回复会由
-- `parent_id` 的级联带走。
--
-- 表还在、函数还在、页面还在：下一份方案上传进去，一切照旧。应用页的评论（`kind = 'app'`）
-- 不在这里，它们是关于应用的，不属于某一份方案。
--
-- Run after 20261119190000_plan_get.sql (or use server/supabase/apply-all.sql).

delete from public.community_comments where kind = 'plan';

delete from public.plans;
