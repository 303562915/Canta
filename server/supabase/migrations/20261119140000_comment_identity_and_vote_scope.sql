-- Comments and votes, second pass: the identity fallback, and a vote scope that answers.
--
-- Two things the first pass got wrong for a phone whose number the backend had not handed out yet:
--
--   * A comment written before `identity_bind` answered was stored with `author_id` equal to the
--     install token's head (the client's fallback). `comments_by_author` only matched the number,
--     so the comment was invisible on "my comments" and `comment_delete` refused it. Both now also
--     match the token itself, which is the secret that proves the same thing.
--   * `package_vote_counts` scoped "this phone" on model + ROM + ROM version. When the app could not
--     read the model yet it sent empty strings, matched nothing, and the bar read 0 votes while
--     "all devices" had some. An empty model now means "no device scope yet": count everything.
--
-- Also adds `package_my_vote`, so the app page can show which side this install already picked
-- instead of trusting a value it remembered locally.
--
-- Run after 20261119130000_comment_threads.sql (or use server/supabase/apply-all.sql).

-- The one-argument versions are replaced by (owner, token): keeping both would make a call with
-- one argument ambiguous for PostgREST.
drop function if exists public.comments_by_author(text);
drop function if exists public.comments_replies_to(text);

/**
 * What one identity wrote, newest first: the comments it started *and* the replies it left.
 *
 * [p_owner] is the identity number; [p_token] is accepted as the same proof, because a comment
 * written before the number arrived was signed with the token instead. Both are matched, so a
 * thread does not split in two over when it was written.
 */
create or replace function public.comments_by_author(
    p_owner text, p_token text default ''
) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint
      from community_comments c
     where c.author_id in (
               coalesce(p_owner, ''),
               coalesce(p_token, ''),
               left(coalesce(p_token, ''), 16)
           )
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
     order by c.created_at desc
     limit 200
$$;

/** The replies other people left under [p_owner]'s comments; [p_token] proves the same identity. */
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
           r.author, r.body, r.created_at, c.body
      from community_comments r
      join community_comments c on c.id = r.parent_id
     where (c.author_id in (
                coalesce(p_owner, ''),
                coalesce(p_token, ''),
                left(coalesce(p_token, ''), 16)
            )
            or (c.author_id = ''
                and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))))
       and r.author_id <> c.author_id
       and r.author_id not in (coalesce(p_owner, ''), coalesce(p_token, ''))
     order by r.created_at desc
     limit 200
$$;

/**
 * Deletes one comment this identity wrote. [p_owner] is the identity number and [p_token] the
 * secret that proves it, exactly like `plan_delete`: a number alone deletes nothing. The token alone
 * is enough when the comment was written before the number arrived.
 */
create or replace function public.comment_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
begin
    if coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.token = p_token) then
        return false;
    end if;
    delete from community_comments c
     where c.id = p_id
       and (c.author_id = coalesce(p_owner, '')
            or c.author_id = p_token
            or c.author_id = left(p_token, 16)
            or (c.author_id = '' and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))));
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

/**
 * Counts both sides for [p_pkg], in two scopes: this device and every device.
 *
 * An empty [p_model] means the caller could not name its phone yet: there is no device scope to
 * report, so that scope is the whole table rather than a zero that reads like "nobody voted".
 */
create or replace function public.package_vote_counts(
    p_pkg text, p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0
) returns jsonb language sql stable security definer set search_path = public as $$
    with scoped as (
        select v.can_remove, v.model, v.codename, v.rom, v.rom_version
        from package_votes v
        where v.pkg = p_pkg
    ), device as (
        select can_remove from scoped
        where coalesce(p_model, '') = ''
           or (
               lower(model) = lower(coalesce(p_model, ''))
               and rom = coalesce(p_rom, '')
               and rom_version = coalesce(p_rom_version, 0)
               and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
           )
    )
    select jsonb_build_object(
        'yes', (select count(*) from device where can_remove),
        'no', (select count(*) from device where not can_remove),
        'all_yes', (select count(*) from scoped where can_remove),
        'all_no', (select count(*) from scoped where not can_remove)
    )
$$;

/** Which side [p_voter] picked for [p_pkg]: true, false, or null when it never voted. */
create or replace function public.package_my_vote(p_pkg text, p_voter text) returns boolean
language sql stable security definer set search_path = public as $$
    select v.can_remove
      from package_votes v
     where v.pkg = p_pkg
       and v.voter = coalesce(p_voter, '')
     limit 1
$$;

revoke all on function public.comments_by_author(text, text) from public;
revoke all on function public.comments_replies_to(text, text) from public;
revoke all on function public.comment_delete(bigint, text, text) from public;
revoke all on function public.package_vote_counts(text, text, text, text, integer) from public;
revoke all on function public.package_my_vote(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comments_by_author(text, text) to anon;
        grant execute on function public.comments_replies_to(text, text) to anon;
        grant execute on function public.comment_delete(bigint, text, text) to anon;
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to anon;
        grant execute on function public.package_my_vote(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comments_by_author(text, text) to authenticated;
        grant execute on function public.comments_replies_to(text, text) to authenticated;
        grant execute on function public.comment_delete(bigint, text, text) to authenticated;
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to authenticated;
        grant execute on function public.package_my_vote(text, text) to authenticated;
    end if;
end $$;
