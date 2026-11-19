-- A display name for each identity, synced through the backend.
--
-- The app has no accounts: a phone owns a random token, and the number that token got (see
-- 20261118180000_user_numbers.sql) is its identity. This migration adds the one thing that is
-- worth syncing between installs: the name the user picked in Settings. Reviews and comments are
-- signed with it, and the avatar next to them is just its first character.
--
-- Both calls answer {id, name}, so a client learns the number and the name in one round trip and
-- never has to guess whether it is signed in.
--
-- Run after 20261118180000_user_numbers.sql (or use server/supabase/apply-all.sql).

alter table public.canta_users
    add column if not exists name text not null default '';

/** The longest name stored; the app stops the user well before this. */
create or replace function public.canta_user_name_max() returns integer
language sql immutable as $$ select 24 $$;

/**
 * Identity and name for [p_token], creating the row on first sight (which also creates the
 * number, starting at 10000). Returns null for a token too short to be one of ours.
 */
create or replace function public.profile_get(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid  bigint;
    unam text;
begin
    if length(coalesce(p_token, '')) < 8 then
        return null;
    end if;
    select id, name into uid, unam from canta_users where token = left(p_token, 120);
    if uid is null then
        insert into canta_users (token) values (left(p_token, 120))
        on conflict (token) do nothing
        returning id into uid;
        if uid is null then
            select id into uid from canta_users where token = left(p_token, 120);
        end if;
        unam := '';
    end if;
    update canta_users set last_seen_at = now() where id = uid;
    return jsonb_build_object('id', uid, 'name', coalesce(unam, ''));
end;
$$;

/**
 * Stores [p_name] for [p_token] and answers the row it wrote, so the phone shows exactly what the
 * backend kept. An empty name clears it, which brings back the install code as the display name.
 */
create or replace function public.profile_set_name(p_token text, p_name text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid  bigint;
    unam text;
begin
    if length(coalesce(p_token, '')) < 8 then
        raise exception 'bad token' using errcode = '22023';
    end if;
    unam := left(btrim(coalesce(p_name, '')), public.canta_user_name_max());
    insert into canta_users (token, name) values (left(p_token, 120), unam)
    on conflict (token) do update
        set name = excluded.name,
            last_seen_at = now()
    returning id, name into uid, unam;
    return jsonb_build_object('id', uid, 'name', unam);
end;
$$;

revoke all on function public.profile_get(text) from public;
revoke all on function public.profile_set_name(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.profile_get(text) to anon;
        grant execute on function public.profile_set_name(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.profile_get(text) to authenticated;
        grant execute on function public.profile_set_name(text, text) to authenticated;
    end if;
end $$;
