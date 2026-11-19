-- Comment threads: one table for every comment the community pages show.
--
-- Until now comments only existed under a plan (`plan_comments`) and could not be answered, which
-- made "did anyone reply to what I wrote?" impossible to ask. This migration puts every comment in
-- one table — plans and app pages alike — gives each one a `parent_id` so a comment can be answered,
-- and adds the read side the app needs to manage its own comments:
--
--   * `comments_for`         one plan's or one app's thread, with the reply count of each comment
--   * `comment_add`          posts a comment, or a reply to one (replies never nest deeper than one)
--   * `comment_delete`       removes a comment the caller wrote, proven by identity number + token
--   * `comments_by_author`   what one identity wrote, with the plan/app it belongs to
--   * `comments_replies_to`  the replies other people left under that identity's comments
--
-- `kind` is 'plan' (target = the plan id as text) or 'app' (target = the package name). The
-- signature (`author`) is the name the person picked, so it can be renamed at any time; `author_id`
-- is the identity number behind it, and that is what ownership is checked against — otherwise
-- renaming yourself would lock you out of deleting your own comments.
--
-- The old `plan_comments` rows are carried over, and `plan_comment` / `plan_comments_for` are
-- re-pointed at the new table so an older app build keeps reading and writing the same thread.
--
-- Run after 20261119120000_package_votes.sql (or use server/supabase/apply-all.sql).

create table if not exists public.community_comments (
    id         bigserial primary key,
    -- 'plan' or 'app': which page the comment hangs under.
    kind       text not null default 'plan',
    -- The plan id (as text) or the package name.
    target     text not null,
    -- The comment this one answers; null for the comment that starts a thread.
    parent_id  bigint references public.community_comments (id) on delete cascade,
    -- The name it is signed with: the nickname from the settings, or "#10000".
    author     text not null default '',
    -- The identity number behind that name: what "my comments" and delete are keyed on.
    author_id  text not null default '',
    -- The phone it was written on, as the writer's app reported it: a comment about removing an app
    -- is only worth as much as the model it is about ("Android 36" alone says nothing).
    device_model    text not null default '',
    android_version text not null default '',
    body       text not null,
    created_at timestamptz not null default now()
);

create index if not exists community_comments_target_idx
    on public.community_comments (kind, target, created_at desc);
create index if not exists community_comments_parent_idx
    on public.community_comments (parent_id);
create index if not exists community_comments_author_idx
    on public.community_comments (author_id, created_at desc);

alter table public.community_comments enable row level security;

-- The plan comments written before this table existed are the same conversation: carry them over.
-- Those rows were signed with the uploader's number, which is also their identity number.
-- The `not exists` guard keeps the copy idempotent, so re-running this file changes nothing.
insert into public.community_comments (kind, target, author, author_id, body, created_at)
select 'plan', c.plan_id::text, c.author, c.author, c.body, c.created_at
  from public.plan_comments c
 where not exists (
     select 1
       from public.community_comments x
      where x.kind = 'plan'
        and x.target = c.plan_id::text
        and x.author = c.author
        and x.body = c.body
        and x.created_at = c.created_at
 );

/**
 * Verified plans for one device, most liked first — unchanged except that the comment count now
 * comes from the shared table, so a reply is counted like a comment.
 */
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test
    from plans p
    where p.reboot_verified
      and lower(p.model) = lower(p_model)
      and (p_codename = '' or lower(p.codename) = lower(p_codename))
      and p.rom = p_rom
      and p.rom_version = p_rom_version
    order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
    limit greatest(1, least(p_limit, 100))
$$;

/** The old plan comment writer: kept so an installed build keeps posting into the same thread. */
create or replace function public.plan_comment(p_id bigint, p_body text, p_author text default '') returns bigint
language plpgsql security definer set search_path = public as $$
declare new_id bigint;
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    insert into community_comments (kind, target, author, author_id, body)
    values ('plan', p_id::text, left(coalesce(p_author, ''), 60), left(coalesce(p_author, ''), 60),
            left(p_body, 1000))
    returning id into new_id;
    return new_id;
end;
$$;

/** The old plan comment reader, in its old shape, over the shared table. */
create or replace function public.plan_comments_for(p_id bigint) returns table (
    author text, body text, created_at timestamptz
) language sql stable security definer set search_path = public as $$
    select author, body, created_at
      from community_comments
     where kind = 'plan' and target = p_id::text
     order by created_at desc
     limit 200
$$;

/**
 * One thread, newest first, each comment with how many replies it collected.
 *
 * [p_target] is the plan id as text for `kind = 'plan'`, the package name for `kind = 'app'`.
 */
create or replace function public.comments_for(p_kind text, p_target text) returns table (
    id bigint, parent_id bigint, author text, body text, created_at timestamptz, replies bigint,
    device_model text, android_version text
) language sql stable security definer set search_path = public as $$
    select c.id, c.parent_id, c.author, c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint,
           c.device_model, c.android_version
      from community_comments c
     where c.kind = coalesce(nullif(p_kind, ''), 'plan')
       and c.target = coalesce(p_target, '')
     order by c.created_at desc
     limit 400
$$;

/**
 * Posts one comment, or one reply to [p_parent], and returns its id.
 *
 * [p_author] is the signature the page shows; [p_author_id] is the identity number behind it, which
 * is what lets the writer delete the comment after renaming themselves. A reply always lands
 * directly under the comment that started the thread: answering a reply answers the thread, so the
 * app only has to render two levels and nobody is quoted at six.
 */
create or replace function public.comment_add(
    p_kind text, p_target text, p_body text, p_author text default '',
    p_parent bigint default null, p_author_id text default '',
    p_model text default '', p_android text default ''
) returns bigint language plpgsql security definer set search_path = public as $$
declare
    new_id bigint;
    root_id bigint;
    kind text := coalesce(nullif(p_kind, ''), 'plan');
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    if length(coalesce(p_target, '')) = 0 then
        raise exception 'missing target' using errcode = '22023';
    end if;

    if p_parent is not null then
        select coalesce(c.parent_id, c.id) into root_id
          from community_comments c
         where c.id = p_parent
           and c.kind = kind
           and c.target = p_target;
        if root_id is null then
            raise exception 'parent comment not found' using errcode = '22023';
        end if;
    end if;

    insert into community_comments (kind, target, parent_id, author, author_id, body,
                                   device_model, android_version)
    values (kind, left(p_target, 200), root_id, left(coalesce(p_author, ''), 60),
            left(coalesce(p_author_id, ''), 60), left(p_body, 1000),
            left(coalesce(p_model, ''), 80), left(coalesce(p_android, ''), 40))
    returning id into new_id;
    return new_id;
end;
$$;

/**
 * Deletes one comment this identity wrote. [p_owner] is the identity number and [p_token] the
 * secret that proves it, exactly like `plan_delete`: a number alone deletes nothing.
 *
 * Ownership is checked on the number, not on the signature, so renaming yourself does not orphan
 * the comments you already wrote. Rows carried over from `plan_comments` have no number column of
 * their own — they were signed with it, so the signature is matched as a fallback.
 *
 * Replies hang off their comment (`on delete cascade`), so removing a thread starter removes the
 * conversation under it — which is what the person deleting it means.
 */
create or replace function public.comment_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
begin
    if coalesce(p_owner, '') = '' or coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.id::text = p_owner and u.token = p_token) then
        return false;
    end if;
    delete from community_comments c
     where c.id = p_id
       and (c.author_id = p_owner
            or (c.author_id = '' and (c.author = p_owner or c.author = '#' || p_owner)));
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

/**
 * What one identity wrote, newest first: the comments it started *and* the replies it left, each
 * with the plan or app it belongs to, so the app can list them and link back.
 *
 * [p_owner] is the identity number.
 */
create or replace function public.comments_by_author(p_owner text) returns table (
    id bigint, kind text, target text, title text, body text,
    created_at timestamptz, replies bigint
) language sql stable security definer set search_path = public as $$
    select c.id, c.kind, c.target,
           coalesce((select left(p.title, 120) from plans p
                      where c.kind = 'plan' and p.id::text = c.target), '') as title,
           c.body, c.created_at,
           (select count(*) from community_comments r where r.parent_id = c.id)::bigint
      from community_comments c
     where c.author_id = coalesce(p_owner, '')
        or (c.author_id = ''
            and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
     order by c.created_at desc
     limit 200
$$;

/**
 * The replies other people left under [p_owner]'s comments, newest first: the answer to "did
 * anybody react to what I wrote?".
 */
create or replace function public.comments_replies_to(p_owner text) returns table (
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
     where (c.author_id = coalesce(p_owner, '')
            or (c.author_id = ''
                and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, ''))))
       and r.author_id <> c.author_id
     order by r.created_at desc
     limit 200
$$;

revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_comment(bigint, text, text) from public;
revoke all on function public.plan_comments_for(bigint) from public;
revoke all on function public.comments_for(text, text) from public;
revoke all on function public.comment_add(text, text, text, text, bigint, text, text, text) from public;
revoke all on function public.comment_delete(bigint, text, text) from public;
revoke all on function public.comments_by_author(text) from public;
revoke all on function public.comments_replies_to(text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_comment(bigint, text, text) to anon;
        grant execute on function public.plan_comments_for(bigint) to anon;
        grant execute on function public.comments_for(text, text) to anon;
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to anon;
        grant execute on function public.comment_delete(bigint, text, text) to anon;
        grant execute on function public.comments_by_author(text) to anon;
        grant execute on function public.comments_replies_to(text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_comment(bigint, text, text) to authenticated;
        grant execute on function public.plan_comments_for(bigint) to authenticated;
        grant execute on function public.comments_for(text, text) to authenticated;
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to authenticated;
        grant execute on function public.comment_delete(bigint, text, text) to authenticated;
        grant execute on function public.comments_by_author(text) to authenticated;
        grant execute on function public.comments_replies_to(text) to authenticated;
    end if;
end $$;
