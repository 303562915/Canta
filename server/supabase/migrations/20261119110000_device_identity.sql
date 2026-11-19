-- Keeps a phone's identity across an uninstall.
--
-- The identity is a random token the phone stores, so uninstalling the app throws it away and the
-- next install would look like a new person with a new number. This migration binds the token to a
-- device key — a hash the app computes from `ANDROID_ID` and the build fingerprint, never a raw
-- hardware identifier — so a reinstall can ask "which token does this phone own?" and get its old
-- one back, with its numbers, plans and name.
--
-- The token stays the secret: the device key is only a lookup key, and it is only ever used to hand
-- the token back to the phone that produced it. A factory reset, or another phone, is a new key and
-- therefore a new identity — that is the intended limit.
--
-- Run after 20261119100000_profile_names.sql (or use server/supabase/apply-all.sql).

create table if not exists public.canta_device_keys (
    device_key text primary key,
    token      text not null,
    created_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now()
);

alter table public.canta_device_keys enable row level security;

/**
 * Answers {token, id, name} for whoever is calling.
 *
 * [p_device_key] is the lookup: when this phone already bound a token, that token wins and the one
 * the caller just generated is dropped by the caller, which adopts the answer. A fresh device key
 * is bound to [p_token]. Both paths end with a `canta_users` row, so the number and the name come
 * back in the same round trip and the app never has to guess whether it is signed in.
 *
 * An empty [p_device_key] keeps working: the call then behaves like `profile_get` and the install
 * keeps its token (web builds have no stable device value).
 */
create or replace function public.identity_bind(p_token text, p_device_key text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid       bigint;
    unam      text;
    key_token text;
    key_hash  text;
    use_token text;
begin
    if length(coalesce(p_token, '')) < 8 then
        raise exception 'bad token' using errcode = '22023';
    end if;

    key_hash := nullif(left(btrim(coalesce(p_device_key, '')), 128), '');
    if key_hash is not null then
        select token into key_token from canta_device_keys where device_key = key_hash;
        if key_token is not null then
            update canta_device_keys set last_seen_at = now() where device_key = key_hash;
            use_token := key_token;
        else
            insert into canta_device_keys (device_key, token)
            values (key_hash, left(p_token, 120))
            on conflict (device_key) do nothing;
            -- Two installs racing on one phone: the loser reads the winner's binding.
            select token into key_token from canta_device_keys where device_key = key_hash;
            use_token := coalesce(key_token, left(p_token, 120));
        end if;
    else
        use_token := left(p_token, 120);
    end if;

    select id, name into uid, unam from canta_users where token = use_token;
    if uid is null then
        insert into canta_users (token) values (use_token)
        on conflict (token) do nothing
        returning id into uid;
        if uid is null then
            select id into uid from canta_users where token = use_token;
        end if;
        unam := '';
    end if;
    update canta_users set last_seen_at = now() where id = uid;

    return jsonb_build_object('token', use_token, 'id', uid, 'name', coalesce(unam, ''));
end;
$$;

revoke all on function public.identity_bind(text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.identity_bind(text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.identity_bind(text, text) to authenticated;
    end if;
end $$;
