-- A comment shows the name its writer has now, not the one they had when they wrote it.
--
-- The row keeps whatever signature was sent with it, which used to be the install code
-- ("E7638-DF160") before the user picked a name, and stays that way in the table forever. Showing
-- it back means a renamed account still looks like a code on its own old comments, which is exactly
-- what "why does it show the code instead of my name" is about.
--
-- `comments_for` now resolves the writer through `canta_users` and falls back to the stored
-- signature only when the row has no identity behind it, and it also returns `author_id` so the
-- page can mark the plan's uploader ("作者") without matching on a display name — two people can
-- call themselves the same thing, and the number cannot.
--
-- Run after 20261119160000_comment_author_backfill.sql (or use server/supabase/apply-all.sql).

-- The shape changes (author_id is new), and a return type cannot be replaced in place.
drop function if exists public.comments_for(text, text);

/**
 * One thread, newest first, each comment with how many replies it collected and the name its
 * writer uses today.
 *
 * [p_target] is the plan id as text for `kind = 'plan'`, the package name for `kind = 'app'`.
 */
create or replace function public.comments_for(p_kind text, p_target text) returns table (
    id bigint, parent_id bigint, author text, author_id text, body text, created_at timestamptz,
    replies bigint, device_model text, system_name text
) language sql stable security definer set search_path = public as $$
    select c.id, c.parent_id,
           coalesce(nullif(u.name, ''), c.author) as author,
           c.author_id,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint,
           c.device_model, c.system_name
      from community_comments c
      left join canta_users u on u.id::text = c.author_id
     where c.kind = coalesce(nullif(p_kind, ''), 'plan')
       and c.target = coalesce(p_target, '')
     order by c.created_at desc
     limit 400
$$;

/** The replies others left under one identity's comments, with the name each writer uses today. */
create or replace function public.comments_replies_to(
    p_owner text, p_token text default ''
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
     order by r.created_at desc
     limit 200
$$;

revoke all on function public.comments_for(text, text) from public;
revoke all on function public.comments_replies_to(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comments_for(text, text) to anon;
        grant execute on function public.comments_replies_to(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comments_for(text, text) to authenticated;
        grant execute on function public.comments_replies_to(text, text) to authenticated;
    end if;
end $$;
