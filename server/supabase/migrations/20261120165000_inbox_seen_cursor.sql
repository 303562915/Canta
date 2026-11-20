-- The red dot's cursor: "what arrived since I last opened the inbox".
--
-- Numbered 16500, not 16000: 16000 was already taken by `plans_all`, which reached the remote
-- first, so two files sharing that version left `supabase db push` stuck on a duplicate
-- `schema_migrations` key for every migration after it. Nothing in this file depends on the number
-- — only on `comment_inbox` having run, which 14000 did.
--
-- `inbox_summary` counted everything that ever happened to what this identity wrote, so the dot
-- meant "you have mail" forever: opening the list cleared it on the device, and the very next count
-- — on the way back to the app list, or after a restart — put the same number back. A message tab
-- is supposed to mean "since you last looked", which is what a short-video app's one is: open it,
-- the number goes away and stays away.
--
-- So the count takes a cursor. `p_seen_at` is an instant the *backend* handed out the last time the
-- page was opened (`checked_at` below), and every source is filtered to rows newer than it. Using a
-- server-stamped instant rather than anything derived from the row ids keeps the comparison honest:
-- hearts have no id of their own to compare against, and a timestamp taken from the device would
-- disagree with the rows whenever a phone's clock is behind.
--
-- Empty or missing means "everything", which is exactly what this function used to answer: an
-- install that has never opened the inbox, and an older app that does not send the argument, both
-- keep the behaviour they had.
--
-- Run after 20261120140000_comment_inbox.sql (or use server/supabase/apply-all.sql).

-- The signature changes, and `create or replace` cannot add an argument: the old two-argument
-- function has to go, or both would exist and PostgREST would keep resolving the old one.
drop function if exists public.inbox_summary(text, text);

/**
 * What is waiting for [p_owner] since [p_seen_at], as four numbers and no rows.
 *
 * Each count is "rows newer than the cursor", which is what the red dot adds up. [checked_at] comes
 * back with them: the instant this answer was taken at, which the page stores and sends as the next
 * call's [p_seen_at]. That round trip is the whole read cursor — nothing is stored server side, and
 * nothing depends on the phone's clock.
 *
 * [newest_comment_id] stays the largest comment id among the comment-shaped events, unfiltered by
 * the cursor: the list still marks individual rows as "newer than the last one I opened".
 */
create or replace function public.inbox_summary(
    p_owner text,
    p_token text default '',
    p_seen_at text default ''
)
returns jsonb language sql stable security definer set search_path = public as $$
    with me as (
        select coalesce(p_owner, '') as owner, coalesce(p_token, '') as token
    ),
    mark as (
        -- The cursor, as an instant. A malformed one (a stored string from an older build, say)
        -- falls back to "everything" rather than failing the count: a red dot that cannot be
        -- computed is worse than one that is too eager.
        select case
                   when coalesce(p_seen_at, '') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                       then left(coalesce(p_seen_at, ''), 40)::timestamptz
               end as ts
    ),
    replies as (
        select count(*)::bigint as n, coalesce(max(r.id), 0) as newest
          from community_comments r
          join community_comments c on c.id = r.parent_id
          cross join me m
          cross join mark
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and r.author_id <> c.author_id
           and r.author_id not in (m.owner, m.token)
           and (mark.ts is null or r.created_at > mark.ts)
    ),
    on_plans as (
        select count(*)::bigint as n, coalesce(max(c.id), 0) as newest
          from community_comments c
          cross join me m
          cross join mark
         where c.kind = 'plan'
           and m.owner <> ''
           and c.target in (
                select p.id::text from plans p
                 where p.owner = m.owner
                    or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16)))
           )
           and c.author_id not in (m.owner, m.token)
           and (mark.ts is null or c.created_at > mark.ts)
    ),
    comment_hearts as (
        select count(*)::bigint as n
          from community_comments c
          cross join me m
          cross join mark
         where (c.author_id in (m.owner, m.token, left(m.token, 16))
                or (c.author_id = ''
                    and (c.author = m.owner or c.author = '#' || m.owner)))
           and exists (select 1 from comment_likes l
                        where l.comment_id = c.id and l.voter not in (m.owner, m.token)
                          and (mark.ts is null or l.created_at > mark.ts))
    ),
    plan_hearts as (
        select count(*)::bigint as n
          from plans p
          cross join me m
          cross join mark
         where m.owner <> ''
           and (p.owner = m.owner
                or (p.owner = '' and p.reporter in (m.owner, m.token, left(m.token, 16))))
           and exists (select 1 from plan_votes v
                        where v.plan_id = p.id and v.voter not in (m.owner, m.token)
                          and (mark.ts is null or v.created_at > mark.ts))
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
        -- Stamped here, in UTC, so the string the app stores compares and parses the same way
        -- whatever time zone the session happens to be in.
        'checked_at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    )
$$;

-- ---------------------------------------------------------------- grants

revoke all on function public.inbox_summary(text, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.inbox_summary(text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.inbox_summary(text, text, text) to authenticated;
    end if;
end $$;

-- The function the app calls changed shape, and a cached schema would answer "no such function" —
-- which the app reads as an older deployment and silently falls back on. Reload it here.
notify pgrst, 'reload schema';