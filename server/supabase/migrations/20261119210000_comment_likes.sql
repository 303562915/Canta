-- Hearts on comments: one heart per identity, and the count that stands next to it.
--
-- A comment thread is read to find out whether the advice worked. A heart is how a reader says
-- "this is what I needed" without writing the same thing again, and it is the only reaction there
-- is: a comment that is wrong is answered, not counted down. That is also how the comment list this
-- page is shaped after works, and two counters would need two explanations.
--
--   * `comment_likes`  one row per (comment, identity). The primary key is what makes a double tap
--                      one heart instead of two, and `on delete cascade` takes the hearts with the
--                      comment they belong to.
--   * `comment_like`   taps the heart on or off and answers the count the page should show, so the
--                      number on screen is the server's, not one the app guessed.
--   * `comments_for`   now reports each comment's heart count and whether the caller is one of them.
--
-- `voter` is the identity number the rest of the comment API is keyed on (`canta_users.id` as
-- text). An install that has not been handed its number yet is still writing comments under the
-- token's head, so both are accepted exactly where the comment writer accepts them.
--
-- Run after 20261119200000_plans_by_owner.sql (or use server/supabase/apply-all.sql).

create table if not exists public.comment_likes (
    comment_id bigint not null references public.community_comments (id) on delete cascade,
    -- The identity number (or its token fallback) that owns the heart: one heart per comment.
    voter      text not null,
    created_at timestamptz not null default now(),
    primary key (comment_id, voter)
);

-- Counting hearts on a page of comments reads the table by comment; the voter index is what makes
-- "did I heart this?" cheap while a list is being rendered.
create index if not exists comment_likes_voter_idx on public.comment_likes (voter);

alter table public.comment_likes enable row level security;

/**
 * Taps the heart on [p_id]: [p_liked] true gives it, false takes it back, and both are safe to
 * repeat — the pair is the primary key, so tapping twice leaves one heart.
 *
 * Answers `{likes, liked}` with the count after the tap. Answers null when there is no comment to
 * heart (deleted while the page was open) or no identity to own the heart: a heart nobody owns is
 * one nobody can take back.
 */
create or replace function public.comment_like(p_id bigint, p_voter text, p_liked boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    voter text := left(coalesce(p_voter, ''), 60);
    total bigint;
begin
    if p_id is null or voter = '' then
        return null;
    end if;
    if not exists (select 1 from community_comments c where c.id = p_id) then
        return null;
    end if;

    if coalesce(p_liked, false) then
        insert into comment_likes (comment_id, voter) values (p_id, voter)
        on conflict (comment_id, voter) do nothing;
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

-- The two-argument reader is replaced by (kind, target, viewer): keeping both would make a call
-- without a viewer ambiguous for PostgREST, which then answers nothing at all.
drop function if exists public.comments_for(text, text);

/**
 * One thread, newest first, each comment with how many replies it collected and how many hearts it
 * has, and whether [p_voter] is one of them.
 *
 * [p_target] is the plan id as text for `kind = 'plan'`, the package name for `kind = 'app'`;
 * an empty [p_voter] simply reports every comment as unhearted, which is what a signed-out page is.
 */
create or replace function public.comments_for(
    p_kind text, p_target text, p_voter text default ''
) returns table (
    id bigint, parent_id bigint, author text, author_id text, body text, created_at timestamptz,
    replies bigint, device_model text, system_name text, likes bigint, liked boolean
) language sql stable security definer set search_path = public as $$
    select c.id, c.parent_id,
           coalesce(nullif(u.name, ''), c.author) as author,
           c.author_id,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint,
           c.device_model, c.system_name,
           (select count(*) from comment_likes l where l.comment_id = c.id)::bigint,
           exists (select 1 from comment_likes l
                    where l.comment_id = c.id and l.voter = coalesce(p_voter, ''))
      from community_comments c
      left join canta_users u on u.id::text = c.author_id
     where c.kind = coalesce(nullif(p_kind, ''), 'plan')
       and c.target = coalesce(p_target, '')
     order by c.created_at desc
     limit 400
$$;

revoke all on function public.comments_for(text, text, text) from public;
revoke all on function public.comment_like(bigint, text, boolean) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comments_for(text, text, text) to anon;
        grant execute on function public.comment_like(bigint, text, boolean) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comments_for(text, text, text) to authenticated;
        grant execute on function public.comment_like(bigint, text, boolean) to authenticated;
    end if;
end $$;
