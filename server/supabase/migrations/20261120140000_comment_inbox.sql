-- The inbox: one feed of everything that happened to what this identity wrote.
--
-- Until now the inbox was one question with one answer — `comments_replies_to`, "did anybody answer
-- me?" — and the page asked for the whole answer at once, 200 rows in a single reply.
--
-- Three things were missing:
--
--   * hearts. A comment can be hearted (`comment_likes`) and a plan can be endorsed (`plan_votes`),
--     and the person who was hearted never learned about it: the count went up on a page they were
--     not looking at.
--   * comments on my plans. `comments_replies_to` joins on comments *of mine*, so somebody writing
--     under a plan I uploaded was invisible here.
--   * a shape that pages. Every reader below takes `limit`/`offset` and clamps both, so "load
--     everything" is not a request the backend can be given, and the app asks for one small page at
--     a time instead of 200 rows that freeze the list while they parse.
--
-- So this migration adds:
--
--   * `comment_likes.author_id`   who was hearted, so a heart can be reported back. Hearted before
--                                 this column existed means nobody can be told after the fact.
--   * `comments_by_targets`       what people wrote under the plans this identity uploaded.
--   * `hearts_for_owner`          my comments that were hearted, newest heart first, one row per
--                                 comment with the tally and the newest voter.
--   * `plan_hearts_for_owner`     my plans that were endorsed, same shape.
--   * `inbox_page`                the four sources merged into one feed, `p_per_source` rows each,
--                                 which is the "消息" list the page shows.
--   * `inbox_summary`             what the red dot counts: four numbers, no rows.
--   * `comments_by_author` / `comments_replies_to`  paged, with the title and the heart count.
--
-- The page size is the same number on both sides by intent: `private.inbox_page_max()` caps every
-- reader, and the app asks for a fifth of it per source, so a slow phone parses 40 short rows rather
-- than a 200-row answer.
--
-- Run after 20261120130000_plan_catalog_market_name_fallback.sql (or use server/supabase/apply-all.sql).

-- ---------------------------------------------------------------- who was hearted

-- The heart already had (comment_id, voter); the recipient is new, and only a heart that names one
-- can be reported to them. Empty on rows written before this column existed: "heart of an unknown
-- person" must not read as "heart of me".
alter table public.comment_likes add column if not exists author_id text not null default '';

-- The feed reads hearts by recipient, newest first, which is exactly this index.
create index if not exists comment_likes_author_idx
    on public.comment_likes (author_id, created_at desc);

/**
 * Taps the heart on [p_id]: [p_liked] true gives it, false takes it back, and both are safe to
 * repeat — the pair is the primary key, so tapping twice leaves one heart.
 *
 * Answers `{likes, liked}` with the count after the tap. Answers null when there is no comment to
 * heart (deleted while the page was open) or no identity to own the heart: a heart nobody owns is
 * one nobody can take back.
 *
 * The heart now records the comment's writer as well as the voter. The count does not need it — the
 * inbox does: without it there is no way to say "three people hearted your comment" to anybody.
 */
create or replace function public.comment_like(p_id bigint, p_voter text, p_liked boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    voter text := left(coalesce(p_voter, ''), 60);
    writer text;
    total bigint;
begin
    if p_id is null or voter = '' then
        return null;
    end if;
    select left(c.author_id, 60) into writer from community_comments c where c.id = p_id;
    if not found then
        return null;
    end if;

    if coalesce(p_liked, false) then
        insert into comment_likes (comment_id, voter, author_id) values (p_id, voter, writer)
        on conflict (comment_id, voter) do update set author_id = excluded.author_id;
    else
        delete from comment_likes l where l.comment_id = p_id and l.voter = voter;
    end if;

    select count(*) into total from comment_likes l where l.comment_id = p_id;
    return jsonb_build_object(
        'likes', total,
        'liked', exists (select 1 from comment_likes l
                          where l.comment_id = p_id and l.voter = voter)
    );
end;
$$;

-- ---------------------------------------------------------------- page size

/** The most rows any inbox reader will hand out in one call. */
create or replace function private.inbox_page_max() returns int language sql immutable set search_path = ''
as $$ select 50 $$;

/**
 * A caller's `limit`, clamped: 1..50, and 20 when it was not given.
 *
 * Every reader below goes through this, which is what keeps "give me everything" from being a
 * possible request.
 */
create or replace function private.inbox_limit(p_limit integer) returns int language sql immutable set search_path = ''
as $$ select greatest(1, least(coalesce(p_limit, 20), private.inbox_page_max())) $$;

/** A caller's `offset`, clamped at 0 and at a depth no page ever reaches. */
create or replace function private.inbox_offset(p_offset integer) returns int language sql immutable set search_path = ''
as $$ select greatest(0, least(coalesce(p_offset, 0), 10000)) $$;

-- ---------------------------------------------------------------- plans I uploaded

/**
 * What people wrote under the plans [p_owner] uploaded, newest first — answers included, because an
 * answer under a comment on my plan is news about my plan.
 *
 * This is the half `comments_replies_to` cannot see: that reader joins on comments *of mine*, and a
 * comment of somebody else on my plan is a different event from a comment of mine anywhere.
 *
 * The uploader is matched on `plans.owner`, the identity number the upload was signed with; a plan
 * from before those numbers existed is matched on the reporter field it was signed with instead.
 * Comments by [p_owner] itself are left out: "you commented your own plan" is not news.
 */
create or replace function public.comments_by_targets(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    id bigint, parent_id bigint, parent_body text, kind text, target text, title text,
    author text, author_id text, body text, created_at timestamptz, likes bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.parent_id,
           coalesce(pc.body, '') as parent_body,
           c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           coalesce(nullif(u.name, ''), c.author) as author,
           c.author_id, c.body, c.created_at,
           (select count(*) from comment_likes l where l.comment_id = c.id)::bigint
      from community_comments c
      left join community_comments pc on pc.id = c.parent_id
      left join canta_users u on u.id::text = c.author_id
     where c.kind = 'plan'
       and c.target in (
            select p.id::text from plans p
             where coalesce(p_owner, '') <> ''
               and (p.owner = p_owner
                    or (p.owner = '' and p.reporter in (coalesce(p_owner, ''),
                                                        coalesce(p_token, ''),
                                                        left(coalesce(p_token, ''), 16))))
       )
       and c.author_id not in (coalesce(p_owner, ''), coalesce(p_token, ''))
     order by c.created_at desc, c.id desc
     limit private.inbox_limit(p_limit)
    offset private.inbox_offset(p_offset)
$$;

-- ---------------------------------------------------------------- hearts on my comments

/**
 * Comments [p_owner] wrote that were hearted, newest heart first, one row per comment.
 *
 * One row per comment, not per heart: ten people hearting the same comment is one line saying ten,
 * which is what that sentence means and what keeps the list from filling with the same comment ten
 * times over. [likes] is the tally, [last_heart_at] and [last_voter] are the news.
 *
 * [last_voter_name] is the name that voter uses today, so a line reads "小张 等 3 人赞了你的评论"
 * instead of naming an identity number.
 */
create or replace function public.hearts_for_owner(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    comment_id bigint, kind text, target text, title text, body text,
    likes bigint, last_heart_at timestamptz, last_voter text, last_voter_name text
) language sql stable security definer set search_path = public as $$
    with grouped as (
        select c.id, c.kind, c.target, c.body,
               count(l.comment_id)::bigint as likes,
               max(l.created_at) as last_heart_at,
               -- The newest voter, which is who the row names: the count is the tally, this is the
               -- face. Taken in the same grouping rather than in a subquery, because an aggregate
               -- cannot be read from inside a correlated subquery.
               (array_agg(l.voter order by l.created_at desc))[1] as last_voter
          from community_comments c
          join comment_likes l on l.comment_id = c.id
         where (c.author_id in (coalesce(p_owner, ''), coalesce(p_token, ''), left(coalesce(p_token, ''), 16))
                or (c.author_id = ''
                    and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))))
           and l.voter not in (coalesce(p_owner, ''), coalesce(p_token, ''))
         group by c.id, c.kind, c.target, c.body
         order by max(l.created_at) desc, c.id desc
         limit private.inbox_limit(p_limit)
        offset private.inbox_offset(p_offset)
    )
    select g.id, g.kind, g.target,
           coalesce((select left(p.title, 120) from plans p
                      where g.kind = 'plan' and p.id::text = g.target), '') as title,
           g.body, g.likes, g.last_heart_at, g.last_voter,
           coalesce((select nullif(u.name, '') from canta_users u
                      where u.id::text = g.last_voter), '') as last_voter_name
      from grouped g
     order by g.last_heart_at desc, g.id desc
$$;

-- ---------------------------------------------------------------- hearts on my plans

/**
 * Plans [p_owner] uploaded that were endorsed, newest endorsement first — the same piece of news
 * as a hearted comment, for the other thing this identity publishes.
 */
create or replace function public.plan_hearts_for_owner(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    plan_id bigint, title text, body text,
    likes bigint, last_heart_at timestamptz, last_voter text, last_voter_name text
) language sql stable security definer set search_path = public as $$
    with grouped as (
        select p.id, left(p.title, 120) as title, left(coalesce(p.note, ''), 200) as note,
               count(v.voter)::bigint as likes,
               max(v.created_at) as last_heart_at,
               (array_agg(v.voter order by v.created_at desc))[1] as last_voter
          from plans p
          join plan_votes v on v.plan_id = p.id
         where coalesce(p_owner, '') <> ''
           and (p.owner = p_owner
                or (p.owner = '' and p.reporter in (coalesce(p_owner, ''),
                                                    coalesce(p_token, ''),
                                                    left(coalesce(p_token, ''), 16))))
           and v.voter not in (coalesce(p_owner, ''), coalesce(p_token, ''))
         group by p.id, p.title, p.note
         order by max(v.created_at) desc, p.id desc
         limit private.inbox_limit(p_limit)
        offset private.inbox_offset(p_offset)
    )
    select g.id, g.title, g.note, g.likes, g.last_heart_at, g.last_voter,
           coalesce((select nullif(u.name, '') from canta_users u
                      where u.id::text = g.last_voter), '') as last_voter_name
      from grouped g
     order by g.last_heart_at desc, g.id desc
$$;

-- ---------------------------------------------------------------- the two list readers, paged

-- Both readers change their return shape (`title`, `likes`), and a return type cannot be replaced in
-- place: drop the old signatures first, so no caller is left on the 200-row version.
drop function if exists public.comments_by_author(text);
drop function if exists public.comments_by_author(text, text);
drop function if exists public.comments_replies_to(text);
drop function if exists public.comments_replies_to(text, text);

/**
 * What one identity wrote, newest first: the comments it started *and* the replies it left, each
 * with the plan or app it belongs to and how many hearts it carries.
 */
create or replace function public.comments_by_author(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint, likes bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint,
           (select count(*) from comment_likes l where l.comment_id = c.id)::bigint
      from community_comments c
     where c.author_id in (coalesce(p_owner, ''), coalesce(p_token, ''), left(coalesce(p_token, ''), 16))
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
     order by c.created_at desc, c.id desc
     limit private.inbox_limit(p_limit)
    offset private.inbox_offset(p_offset)
$$;

/**
 * The replies other people left under [p_owner]'s comments, newest first — the "somebody answered
 * me" source of the feed, paged like the reader above.
 */
create or replace function public.comments_replies_to(
    p_owner text, p_token text default '', p_limit integer default 20, p_offset integer default 0
) returns table (
    id bigint, parent_id bigint, kind text, target text, title text,
    author text, body text, created_at timestamptz, parent_body text
) language sql stable security definer set search_path = public as $$
    select r.id, c.id,
           r.kind, r.target,
           coalesce((select left(p.title, 120) from plans p
                      where r.kind = 'plan' and p.id::text = r.target), '') as title,
           coalesce(nullif(ru.name, ''), r.author) as author,
           r.body, r.created_at, c.body
      from community_comments r
      join community_comments c on c.id = r.parent_id
      left join canta_users ru on ru.id::text = r.author_id
     where (c.author_id in (
                coalesce(p_owner, ''),
                coalesce(p_token, ''),
                left(coalesce(p_token, ''), 16)
            )
            or (c.author_id = ''
                and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
            or (coalesce(p_owner, '') <> ''
                and c.author_id !~ '^[0-9]+$'
                and c.author = coalesce((select u.name from canta_users u
                                          where u.id::text = p_owner and u.name <> ''), '')))
       and r.author_id <> c.author_id
       and r.author_id not in (coalesce(p_owner, ''), coalesce(p_token, ''))
     order by r.created_at desc, r.id desc
     limit private.inbox_limit(p_limit)
    offset private.inbox_offset(p_offset)
$$;

-- ---------------------------------------------------------------- the feed

/**
 * The four sources merged into one list, newest first: what the "消息" tab shows.
 *
 * [p_per_source] rows are taken from each source at [p_offset], so the list grows by asking for the
 * next offset rather than by asking for "more" and hoping: page N of a source is the same rows
 * whatever else happened in between, and a source that runs out simply stops contributing. Merging
 * in SQL means one request per scroll instead of four, and the order is the server's.
 *
 * The `src` column says which source a row came from, and is part of the sort: it is what tells the
 * page whether to draw a reply, a heart on a comment or a heart on a plan, and it keeps the order
 * total when two events share a timestamp.
 *
 * Rows are ≤ 4 × `private.inbox_page_max()` by construction, and 40 in practice.
 */
create or replace function public.inbox_page(
    p_owner text, p_token text default '', p_per_source integer default 10, p_offset integer default 0
) returns table (
    src text, src_id bigint, kind text, target text, title text,
    body text, parent_body text, actor text, actor_name text,
    likes bigint, created_at timestamptz
) language sql stable security definer set search_path = public as $$
    with feed as (
        select 'reply'::text as src, r.id as src_id, r.kind, r.target, r.title,
               r.body, r.parent_body, r.author as actor, r.author as actor_name,
               0::bigint as likes, r.created_at
          from public.comments_replies_to(p_owner, p_token, p_per_source, p_offset) r
        union all
        select 'plan_comment', c.id, c.kind, c.target, c.title,
               c.body, c.parent_body, c.author, c.author,
               c.likes, c.created_at
          from public.comments_by_targets(p_owner, p_token, p_per_source, p_offset) c
        union all
        select 'comment_heart', h.comment_id, h.kind, h.target, h.title,
               h.body, ''::text, h.last_voter, h.last_voter_name,
               h.likes, h.last_heart_at
          from public.hearts_for_owner(p_owner, p_token, p_per_source, p_offset) h
        union all
        select 'plan_heart', ph.plan_id, 'plan'::text, ph.plan_id::text, ph.title,
               ph.body, ''::text, ph.last_voter, ph.last_voter_name,
               ph.likes, ph.last_heart_at
          from public.plan_hearts_for_owner(p_owner, p_token, p_per_source, p_offset) ph
    )
    select f.src, f.src_id, f.kind, f.target, f.title,
           f.body, f.parent_body, f.actor, f.actor_name, f.likes, f.created_at
      from feed f
     order by f.created_at desc, f.src desc, f.src_id desc
$$;

-- ---------------------------------------------------------------- the red dot

/**
 * What is waiting for [p_owner], as four numbers and no rows: the counts the red dot adds up.
 *
 * The dot used to be "replies newer than the last id I opened", which was the whole feed when
 * replies were the whole feed. Now hearts, comments on my plans and endorsements of my plans are
 * feed too, so the dot is the sum of the four — asked of the server, which is the only place that
 * knows, and cheap because each one is an indexed count rather than a page of rows.
 *
 * [newest_comment_id] is the largest comment id among the comment-shaped events, so the page can
 * still mark "newer than the last one I opened" on individual rows.
 */
create or replace function public.inbox_summary(p_owner text, p_token text default '')
returns jsonb language sql stable security definer set search_path = public as $$
    with me as (
        select coalesce(p_owner, '') as owner, coalesce(p_token, '') as token
    ),
    replies as (
        select count(*)::bigint as n, coalesce(max(r.id), 0) as newest
          from community_comments r
          join community_comments c on c.id = r.parent_id
          cross join me m
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and r.author_id <> c.author_id
           and r.author_id not in (m.owner, m.token)
    ),
    on_plans as (
        select count(*)::bigint as n, coalesce(max(c.id), 0) as newest
          from community_comments c
          cross join me m
         where c.kind = 'plan'
           and m.owner <> ''
           and c.target in (
                select p.id::text from plans p
                 where p.owner = m.owner
                    or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16)))
           )
           and c.author_id not in (m.owner, m.token)
    ),
    comment_hearts as (
        select count(*)::bigint as n
          from community_comments c
          cross join me m
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and exists (select 1 from comment_likes l
                        where l.comment_id = c.id and l.voter not in (m.owner, m.token))
    ),
    plan_hearts as (
        select count(*)::bigint as n
          from plans p
          cross join me m
         where m.owner <> ''
           and (p.owner = m.owner
                or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16))))
           and exists (select 1 from plan_votes v
                        where v.plan_id = p.id and v.voter not in (m.owner, m.token))
    )
    select jsonb_build_object(
        'replies', (select n from replies),
        'plan_comments', (select n from on_plans),
        'comment_hearts', (select n from comment_hearts),
        'plan_hearts', (select n from plan_hearts),
        'newest_comment_id', greatest(
            (select newest from replies),
            (select newest from on_plans)
        )
    )
$$;

-- ---------------------------------------------------------------- grants

revoke all on function public.comment_like(bigint, text, boolean) from public;
revoke all on function public.comments_by_targets(text, text, integer, integer) from public;
revoke all on function public.hearts_for_owner(text, text, integer, integer) from public;
revoke all on function public.plan_hearts_for_owner(text, text, integer, integer) from public;
revoke all on function public.inbox_page(text, text, integer, integer) from public;
revoke all on function public.inbox_summary(text, text) from public;
revoke all on function public.comments_by_author(text, text, integer, integer) from public;
revoke all on function public.comments_replies_to(text, text, integer, integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comment_like(bigint, text, boolean) to anon;
        grant execute on function public.comments_by_targets(text, text, integer, integer) to anon;
        grant execute on function public.hearts_for_owner(text, text, integer, integer) to anon;
        grant execute on function public.plan_hearts_for_owner(text, text, integer, integer) to anon;
        grant execute on function public.inbox_page(text, text, integer, integer) to anon;
        grant execute on function public.inbox_summary(text, text) to anon;
        grant execute on function public.comments_by_author(text, text, integer, integer) to anon;
        grant execute on function public.comments_replies_to(text, text, integer, integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comment_like(bigint, text, boolean) to authenticated;
        grant execute on function public.comments_by_targets(text, text, integer, integer) to authenticated;
        grant execute on function public.hearts_for_owner(text, text, integer, integer) to authenticated;
        grant execute on function public.plan_hearts_for_owner(text, text, integer, integer) to authenticated;
        grant execute on function public.inbox_page(text, text, integer, integer) to authenticated;
        grant execute on function public.inbox_summary(text, text) to authenticated;
        grant execute on function public.comments_by_author(text, text, integer, integer) to authenticated;
        grant execute on function public.comments_replies_to(text, text, integer, integer) to authenticated;
    end if;
end $$;