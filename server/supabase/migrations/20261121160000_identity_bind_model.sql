-- The identity row learns which phone it is, at the moment it is created.
--
-- `canta_users.model` was only ever written by `user_login`, which the app calls when the community
-- page opens. Most people never open it, so the table held 594 identities and 45 models — a 92% blank
-- rate that reads like "the app cannot recognise phones", when in fact the model was simply never
-- sent. It also made `plan_catalog`'s `model_people` count lower than reality: only people who
-- uploaded or posted were ever matched to a model.
--
-- `identity_bind` is the call every install makes on first launch (and on every start after), so the
-- model and codename travel with it now. Both are the same `Build.MODEL` / `Build.DEVICE` values
-- `user_login` already stores — no hardware identifier, no fingerprint, nothing that an empty
-- `p_model` would not simply leave out.
--
-- The two-argument form is dropped rather than kept alongside: with defaults present PostgREST would
-- see two candidates for a call that names only `p_token` / `p_device_key` and answer "not unique".
-- Old clients keep working because the new function defaults both new arguments to ''.
--
-- Run after 20261121150000_device_name_seed.sql (or use server/supabase/apply-all.sql).

drop function if exists public.identity_bind(text, text);

create or replace function public.identity_bind(
    p_token text,
    p_device_key text default '',
    p_model text default '',
    p_codename text default ''
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    uid       bigint;
    unam      text;
    key_token text;
    key_hash  text;
    use_token text;
    use_model text;
    use_code  text;
begin
    if length(coalesce(p_token, '')) < 8 then
        raise exception 'bad token' using errcode = '22023';
    end if;

    use_model := nullif(left(btrim(coalesce(p_model, '')), 120), '');
    use_code  := nullif(left(btrim(coalesce(p_codename, '')), 120), '');

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
        insert into canta_users (token, model, codename)
        values (use_token, coalesce(use_model, ''), coalesce(use_code, ''))
        on conflict (token) do nothing
        returning id into uid;
        if uid is null then
            select id into uid from canta_users where token = use_token;
        end if;
        unam := '';
    end if;

    -- Keeps the last value the phone reported: an empty argument (a web build, a read that failed)
    -- must not wipe a model an earlier call knew.
    update canta_users
       set last_seen_at = now(),
           model    = coalesce(use_model, model),
           codename = coalesce(use_code, codename)
     where id = uid;

    return jsonb_build_object('token', use_token, 'id', uid, 'name', coalesce(unam, ''));
end;
$$;

revoke all on function public.identity_bind(text, text, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.identity_bind(text, text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.identity_bind(text, text, text, text) to authenticated;
    end if;
end $$;

-- 函数换了签名，缓存里的 schema 还只认识旧的那个；不重载的话 App 第一次调用会拿到
-- "没有这个函数"，被它读成后端不可达。
notify pgrst, 'reload schema';