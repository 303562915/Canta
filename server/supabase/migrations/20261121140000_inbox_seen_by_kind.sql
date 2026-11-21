-- 每一栏消息各自的已读位置。
--
-- 消息中心分四栏（回复 / 方案评论 / 赞），但已读位置只有一个：`inbox_summary` 一次回答四个
-- 数字，四个数字都用同一个 `p_seen_at` 过滤，而游标本身还不在库里——它记在手机上
-- （`AppNoteStore.markInboxSeen`），服务端只负责把 `checked_at` 这个瞬间发回来。
--
-- 于是一个游标管四栏：把回复栏点开，其它三栏的红点跟着一起清掉，"谁读过"被记成了"四栏都读过"。
--
-- 这里补上前半截：一个身份一栏一行，各存各的时间戳。四个 `kind` 就是 `inbox_page.src` 用的
-- 四个名字，别的地方不用再翻译一次。
--
-- 只加不删。`inbox_summary(text, text, text)` 原样留着——旧客户端没有"栏"的概念，还在调那个
-- 签名，它不能消失。新客户端用另一支函数 `inbox_summary_kinds(...)`，找不到（PostgREST 的
-- `PGRST202`）就退回旧的那一支，行为与今天完全一致。名字不同而不是同名的第四五六个参数，
-- 是因为 `20261120165000_inbox_seen_cursor.sql` 已经踩过一次：同名多签名并存时 PostgREST 会
-- 一直解析到旧的那个。
--
-- 写入也补上了：`inbox_seen_mark(...)` 按栏往前推位置，`greatest` 保证晚到的旧时刻不会把
-- 已读位置拉回去。换机重装时，新装的那台从库里读到的位置就是上一台读过的位置，而不是从零
-- 再炸一遍历史红点。
--
-- Run after 20261121130000_healthz.sql (or use server/supabase/apply-all.sql).

create schema if not exists private;

-- 一个身份一行一栏：主键就是"同一栏只留一行"，写第二次是更新而不是追加。
create table if not exists public.inbox_seen (
    user_id    bigint not null references public.canta_users (id) on delete cascade,
    kind       text   not null check (kind in ('reply', 'plan_comment', 'comment_heart', 'plan_heart')),
    seen_at    timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (user_id, kind)
);

-- 和 `plans`、`canta_users` 一样：表只给下面的 definer 函数用，客户端没有直接读写的路。
alter table public.inbox_seen enable row level security;

/**
 * 把"身份码 + 令牌"解析成 `canta_users.id`。
 *
 * 客户端有两个东西：`p_owner` 是身份码（"10000"），`p_token` 是它的秘密。两个都给的时候以
 * 身份码为准；只给令牌（还没拿到身份码的第一次调用）也能落到同一行上。
 */
create or replace function private.inbox_uid(p_owner text, p_token text)
returns bigint language sql stable security definer set search_path = public as $$
    select u.id
      from public.canta_users u
     where (coalesce(p_owner, '') <> '' and u.id::text = p_owner)
        or (coalesce(p_token, '') <> '' and u.token = p_token)
     order by (u.id::text = coalesce(p_owner, '')) desc
     limit 1
$$;

/**
 * 四栏各自的"还差多少"，每栏用自己的游标算。
 *
 * 参数按栏给：`p_seen_reply` / `p_seen_plan_comment` / `p_seen_comment_heart` /
 * `p_seen_plan_heart`，名字与 `inbox_page.src` 一致。某一栏给空字符串时用库里那一栏存的
 * 位置——这是新装的那台手机不需要先把库里的位置问一遍的原因；两边都没有才是"从头算"，
 * 也就是旧函数的意思。
 *
 * [checked_at] 还是这一次计算的瞬间，和旧函数一样由后端盖戳，客户端存下来当地一次比较的
 * 基准。`seen` 把每栏实际用到的位置回传：客户端拿到的可能是库里存的那个，不一定是自己发的。
 *
 * 四个数字、`newest_comment_id` 的算法与 `inbox_summary` 逐条相同，只是把它们从"一个游标"
 * 换成"四个游标"——两处不一致的话，栏上的数字和红点就会各说各话。
 */
create or replace function public.inbox_summary_kinds(
    p_owner text,
    p_token text default '',
    p_seen_reply text default '',
    p_seen_plan_comment text default '',
    p_seen_comment_heart text default '',
    p_seen_plan_heart text default ''
)
returns jsonb language sql stable security definer set search_path = public as $$
    with me as (
        select coalesce(p_owner, '') as owner, coalesce(p_token, '') as token
    ),
    stored as (
        select s.kind, s.seen_at
          from public.inbox_seen s
         where s.user_id = private.inbox_uid(p_owner, p_token)
    ),
    asked (kind, at) as (
        values
            ('reply', coalesce(p_seen_reply, '')),
            ('plan_comment', coalesce(p_seen_plan_comment, '')),
            ('comment_heart', coalesce(p_seen_comment_heart, '')),
            ('plan_heart', coalesce(p_seen_plan_heart, ''))
    ),
    mark as (
        -- 每栏一个上界。格式不对的字符串（旧版本存下来的、被改坏的值）当作"没给"，
        -- 落到库里那一栏的位置上；库里也没有就是 null = 从头算，红点宁可多亮一次也不该算不出来。
        select a.kind,
               case
                   when a.at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' then left(a.at, 40)::timestamptz
                   else s.seen_at
               end as ts
          from asked a
          left join stored s on s.kind = a.kind
    ),
    replies as (
        select count(*)::bigint as n, coalesce(max(r.id), 0) as newest
          from community_comments r
          join community_comments c on c.id = r.parent_id
          cross join me m
          cross join (select ts from mark where kind = 'reply') k
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and r.author_id <> c.author_id
           and r.author_id not in (m.owner, m.token)
           and (k.ts is null or r.created_at > k.ts)
    ),
    on_plans as (
        select count(*)::bigint as n, coalesce(max(c.id), 0) as newest
          from community_comments c
          cross join me m
          cross join (select ts from mark where kind = 'plan_comment') k
         where c.kind = 'plan'
           and m.owner <> ''
           and c.target in (
                select p.id::text from plans p
                 where p.owner = m.owner
                    or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16)))
           )
           and c.author_id not in (m.owner, m.token)
           and (k.ts is null or c.created_at > k.ts)
    ),
    comment_hearts as (
        select count(*)::bigint as n
          from community_comments c
          cross join me m
          cross join (select ts from mark where kind = 'comment_heart') k
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and exists (select 1 from comment_likes l
                        where l.comment_id = c.id and l.voter not in (m.owner, m.token)
                          and (k.ts is null or l.created_at > k.ts))
    ),
    plan_hearts as (
        select count(*)::bigint as n
          from plans p
          cross join me m
          cross join (select ts from mark where kind = 'plan_heart') k
         where m.owner <> ''
           and (p.owner = m.owner
                or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16))))
           and exists (select 1 from plan_votes v
                        where v.plan_id = p.id and v.voter not in (m.owner, m.token)
                          and (k.ts is null or v.created_at > k.ts))
    )
    select jsonb_build_object(
        'replies', (select n from replies),
        'plan_comments', (select n from on_plans),
        'comment_hearts', (select n from comment_hearts),
        'plan_hearts', (select n from plan_hearts),
        'newest_comment_id', greatest(
            (select newest from replies),
            (select newest from on_plans)
        ),
        -- 与旧函数同格式，同一时区，客户端的字符串比较才有意义。
        'checked_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        -- 每栏实际用到的位置；没给也没存的栏不出现在这里（客户端就当它是空）。
        'seen', coalesce((
            select jsonb_object_agg(kind, to_char(ts at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
              from mark
             where ts is not null
        ), '{}'::jsonb)
    )
$$;

/**
 * 把四栏的已读位置往前推。
 *
 * 只有往前：`greatest` 让一个晚到的旧时刻（慢回答、时钟差）改不动已经读过的位置，和本地
 * `AppNoteStore.markInboxSeen` 的规则一样，两边不会互相拉扯。
 *
 * 没有身份（还没拿到身份码，或者令牌不认识）时什么也不写、答 `ok = false`：位置只留在本机，
 * 这和今天完全一样，不是错误。
 */
create or replace function public.inbox_seen_mark(
    p_owner text,
    p_token text default '',
    p_seen_reply text default '',
    p_seen_plan_comment text default '',
    p_seen_comment_heart text default '',
    p_seen_plan_heart text default ''
)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    uid bigint := private.inbox_uid(p_owner, p_token);
begin
    if uid is null then
        return jsonb_build_object('ok', false);
    end if;
    insert into public.inbox_seen as s (user_id, kind, seen_at, updated_at)
    select uid, v.kind, left(v.at, 40)::timestamptz, now()
      from (values
                ('reply', coalesce(p_seen_reply, '')),
                ('plan_comment', coalesce(p_seen_plan_comment, '')),
                ('comment_heart', coalesce(p_seen_comment_heart, '')),
                ('plan_heart', coalesce(p_seen_plan_heart, ''))
           ) as v (kind, at)
     where v.at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
    on conflict (user_id, kind) do update
        set seen_at = greatest(s.seen_at, excluded.seen_at),
            updated_at = now();
    return jsonb_build_object(
        'ok', true,
        'seen', coalesce((
            select jsonb_object_agg(k.kind, to_char(k.seen_at at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
              from public.inbox_seen k
             where k.user_id = uid
        ), '{}'::jsonb)
    );
end;
$$;

-- ---------------------------------------------------------------- grants

revoke all on function public.inbox_summary_kinds(text, text, text, text, text, text) from public;
revoke all on function public.inbox_seen_mark(text, text, text, text, text, text) from public;
revoke all on function private.inbox_uid(text, text) from public, anon, authenticated;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.inbox_summary_kinds(text, text, text, text, text, text) to anon;
        grant execute on function public.inbox_seen_mark(text, text, text, text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.inbox_summary_kinds(text, text, text, text, text, text) to authenticated;
        grant execute on function public.inbox_seen_mark(text, text, text, text, text, text) to authenticated;
    end if;
end $$;

-- 两支新函数，缓存里的 schema 还不知道它们；不重载的话客户端第一次调用会拿到"没有这个函数"，
-- 被它读成旧部署然后退回旧游标。
notify pgrst, 'reload schema';

-- Run after 20261121130000_healthz.sql (or use server/supabase/apply-all.sql).