-- "My comments" was empty because older rows were signed with a name, not a number.
--
-- `comment_add` stores the identity number in `author_id`, and everything the page reads matches on
-- it. Three batches of rows predate that: the ones carried over from `plan_comments` kept the
-- signature as their id, and the app used to send the display name ("开发者") or the token's code
-- ("E7638-DF160") instead of the number whenever `identity_bind` had not answered yet. Those rows
-- belong to somebody, and "my comments" has to find them.
--
-- Two parts:
--
--   * backfill — rewrite those ids into the number the same person owns, matched on the name they
--     picked and on the code their token produces (first 10 characters, 5+5, upper case);
--   * fallback — `comments_by_author`, `comments_replies_to` and `comment_delete` also accept a
--     non-numeric id that equals the caller's name, so a row written before this ran is still
--     listed and still deletable even if it could not be converted.
--
-- Run after 20261119150000_comment_add_variable_fix.sql (or use server/supabase/apply-all.sql).

-- The names people picked: an id that equals a name belongs to that account.
update public.community_comments c
   set author_id = u.id::text
  from public.canta_users u
 where u.name <> ''
   and c.author_id = u.name;

-- The install codes: `DeviceIdentity.codeOf` is the token's first 10 alphanumerics, upper-cased,
-- padded with '0' and cut into two groups of five. Rebuild the same string from the token.
with codes as (
    select u.id,
           upper(substr(rpad(clean, 10, '0'), 1, 5) || '-' || substr(rpad(clean, 10, '0'), 6, 5)) as code
      from (
          select id, upper(regexp_replace(token, '[^A-Za-z0-9]', '', 'g')) as clean
            from public.canta_users
      ) u
)
update public.community_comments c
   set author_id = codes.id::text
  from codes
 where c.author_id = codes.code;

/** What one identity wrote, newest first; a leftover name counts as that identity. */
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
        -- A row that still carries a name instead of a number: accept it when the name is the one
        -- this identity picked. Only for non-numeric ids, so a real number is never matched by name.
        or (coalesce(p_owner, '') <> ''
            and c.author_id !~ '^[0-9]+$'
            and c.author = coalesce((select u.name from canta_users u
                                      where u.id::text = p_owner and u.name <> ''), ''))
     order by c.created_at desc
     limit 200
$$;

/** The replies other people left under [p_owner]'s comments; the same name fallback applies. */
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

/** Deletes one comment this identity wrote, including a row still signed with its name. */
create or replace function public.comment_delete(p_id bigint, p_owner text, p_token text) returns boolean
language plpgsql security definer set search_path = public as $$
declare
    removed integer;
    my_name text;
begin
    if coalesce(p_token, '') = '' then
        return false;
    end if;
    if not exists (select 1 from canta_users u where u.token = p_token) then
        return false;
    end if;
    select u.name into my_name from canta_users u where u.token = p_token;
    delete from community_comments c
     where c.id = p_id
       and (c.author_id = coalesce(p_owner, '')
            or c.author_id = p_token
            or c.author_id = left(p_token, 16)
            or (c.author_id = '' and (c.author = coalesce(p_owner, '') or c.author = '#' || coalesce(p_owner, '')))
            or (c.author_id !~ '^[0-9]+$'
                and my_name is not null and my_name <> '' and c.author = my_name));
    get diagnostics removed = row_count;
    return removed > 0;
end;
$$;

revoke all on function public.comments_by_author(text, text) from public;
revoke all on function public.comments_replies_to(text, text) from public;
revoke all on function public.comment_delete(bigint, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comments_by_author(text, text) to anon;
        grant execute on function public.comments_replies_to(text, text) to anon;
        grant execute on function public.comment_delete(bigint, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comments_by_author(text, text) to authenticated;
        grant execute on function public.comments_replies_to(text, text) to authenticated;
        grant execute on function public.comment_delete(bigint, text, text) to authenticated;
    end if;
end $$;
