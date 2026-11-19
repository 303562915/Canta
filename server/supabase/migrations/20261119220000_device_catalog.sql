-- The device catalog: which phones the community has plans for, on which builds, and how many
-- people joined each one.
--
-- The safety page used to speak about exactly one device — the caller's. This adds the other half:
-- a list the page can draw as chips (model → build), so a plan can be read before the same phone
-- arrives, and so "this model has nothing yet" is a fact the page can show instead of an empty
-- list. Nothing here changes what a plan is matched against; `plans_for` still serves the caller's
-- own build, and `plans_for_model` is the explicitly named door for browsing somebody else's.
--
-- People are counted per identity, with the same identity string on both sides:
--   'o:<number>'  — an install that owns the plan (or the user row it registered with)
--   'r:<reporter>' — a plan uploaded before owners existed
-- so one person who registered *and* uploaded counts once.
--
-- The model's display name is the one the uploader's ROM reported ("Redmi K70" instead of
-- "23113RKC6C"), stored from now on in `market_name`; older rows have none and fall back to the
-- retail model number, which is what the ROM called them.
--
-- Run after 20261119210000_comment_likes.sql (or use server/supabase/apply-all.sql).

alter table public.plans add column if not exists market_name text not null default '';

/**
 * Stores one plan, now with the model's marketing name when the uploader's ROM has one.
 *
 * The signature and every rule stay as they were: a reboot proof, an owner, at most 200 packages.
 */
create or replace function public.plan_submit(p_plan jsonb) returns bigint
language plpgsql security definer set search_path = public as $$
declare
    new_id bigint;
    pkgs text[];
    plan_owner text;
begin
    if coalesce((p_plan->>'reboot_verified')::boolean, false) is not true then
        raise exception 'plan not verified by a reboot' using errcode = '22023';
    end if;
    if p_plan->>'rebooted_at' is null then
        raise exception 'missing reboot time' using errcode = '22023';
    end if;
    plan_owner := left(coalesce(p_plan->>'owner', ''), 120);
    select array_agg(value) into pkgs from jsonb_array_elements_text(p_plan->'packages') as value;
    if pkgs is null or array_length(pkgs, 1) is null or array_length(pkgs, 1) = 0 or array_length(pkgs, 1) > 200 then
        raise exception 'bad package list' using errcode = '22023';
    end if;

    insert into plans (brand, model, market_name, codename, rom, rom_version, sdk, title, note, packages,
                       reboot_verified, rebooted_at, reporter, owner, is_test)
    values (coalesce(p_plan->>'brand', 'unknown'), coalesce(p_plan->>'model', 'unknown'),
            left(coalesce(p_plan->>'market_name', ''), 80),
            coalesce(p_plan->>'codename', ''), coalesce(p_plan->>'rom', 'unknown'),
            coalesce((p_plan->>'rom_version')::int, 0), coalesce((p_plan->>'sdk')::int, 0),
            left(coalesce(p_plan->>'title', 'Untitled'), 120), left(coalesce(p_plan->>'note', ''), 2000),
            pkgs, true, (p_plan->>'rebooted_at')::timestamptz,
            left(coalesce(p_plan->>'reporter', plan_owner), 120), plan_owner,
            coalesce((p_plan->>'test')::boolean, false))
    returning id into new_id;
    return new_id;
end;
$$;

-- The shape grows by the device columns, and a return type cannot be replaced in place: every
-- function that answers with a plan row is dropped and rebuilt below, all with the same columns,
-- so the app keeps reading them through one parser.
drop function if exists public.plans_for(text, text, text, integer, integer);
drop function if exists public.plan_get(bigint);
drop function if exists public.plans_by_owner(text);

/**
 * Verified plans for one device, most liked first, now carrying the device each plan was made on.
 *
 * Matching is unchanged: exact model, optional codename, exact ROM and ROM version. The device
 * columns are what lets a row say "this plan is not for this phone" without a second call.
 */
create or replace function public.plans_for(
    p_model text, p_codename text, p_rom text, p_rom_version integer, p_limit integer default 50
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
    from plans p
    left join canta_users u on u.id::text = p.owner
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

/** One plan by id, for the pages that open a plan from a comment, a share code or another model. */
create or replace function public.plan_get(p_id bigint) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.id = p_id
     limit 1
$$;

/** Every plan one identity uploaded, whatever device it was matched to, newest first. */
create or replace function public.plans_by_owner(p_owner text) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
      from plans p
      left join canta_users u on u.id::text = p.owner
     where coalesce(p_owner, '') <> ''
       and p.owner = p_owner
     order by p.created_at desc
     limit 200
$$;

/**
 * The plans of another model — the browser behind the model chips.
 *
 * [p_brand] narrows the match when two makers sell a phone under one model string; an empty one
 * accepts every brand. [p_rom] empty (with [p_rom_version] 0) means "all builds of this model",
 * which is what the "全部" chip asks for. Matching is still exact on the model: this is not a
 * fuzzy search, it is the same phone sold somewhere else.
 */
create or replace function public.plans_for_model(
    p_model text, p_brand text default '', p_rom text default '', p_rom_version integer default 0,
    p_limit integer default 100
) returns table (
    id bigint, title text, note text, packages text[], votes bigint, comments bigint,
    created_at timestamptz, rebooted_at timestamptz, owner text, is_test boolean, owner_name text,
    brand text, model text, market_name text, rom text, rom_version integer
) language sql stable security definer set search_path = public as $$
    select p.id, p.title, p.note, p.packages,
           (select count(*) from plan_votes v where v.plan_id = p.id)::bigint,
           (select count(*) from community_comments c
             where c.kind = 'plan' and c.target = p.id::text)::bigint,
           p.created_at, p.rebooted_at, p.owner, p.is_test,
           coalesce(nullif(u.name, ''), '') as owner_name,
           p.brand, p.model, coalesce(p.market_name, ''), p.rom, p.rom_version
      from plans p
      left join canta_users u on u.id::text = p.owner
     where p.reboot_verified
       and coalesce(p_model, '') <> ''
       and lower(p.model) = lower(p_model)
       and (coalesce(p_brand, '') = '' or lower(p.brand) = lower(p_brand))
       and (
             coalesce(p_rom, '') = ''
             or (p.rom = p_rom and (coalesce(p_rom_version, 0) = 0 or p.rom_version = p_rom_version))
           )
     order by
        p.is_test asc,
        (select count(*) from plan_votes v where v.plan_id = p.id) desc,
        p.created_at desc
     limit greatest(1, least(coalesce(p_limit, 100), 200))
$$;

/**
 * Every model the community has plans for, one row per build, with the counts the chips draw.
 *
 * `plans` / `people` are the row's own build; `model_plans` / `model_people` count the whole model
 * — the person who registered on the model but never uploaded is part of "加入", and the app shows
 * that number only when it is worth reading (more than a handful).
 */
create or replace function public.plan_catalog() returns table (
    brand text, model text, market_name text, rom text, rom_version integer,
    plans bigint, people bigint, model_plans bigint, model_people bigint
) language sql stable security definer set search_path = public as $$
    with builds as (
        select coalesce(nullif(p.brand, ''), 'unknown') as brand,
               p.model,
               p.rom,
               p.rom_version,
               count(*)::bigint as plans,
               count(distinct case
                        when coalesce(p.owner, '') <> '' then 'o:' || p.owner
                        else 'r:' || p.reporter
                      end)::bigint as people
          from plans p
         where coalesce(p.model, '') <> ''
         group by 1, 2, 3, 4
    ), models as (
        select b.brand,
               b.model,
               (select coalesce(p2.market_name, '')
                  from plans p2
                 where lower(p2.model) = lower(b.model)
                   and coalesce(p2.market_name, '') <> ''
                 order by p2.created_at desc
                 limit 1) as market_name,
               sum(b.plans)::bigint as model_plans,
               (select count(distinct ident)::bigint from (
                    select case
                             when coalesce(p3.owner, '') <> '' then 'o:' || p3.owner
                             else 'r:' || p3.reporter
                           end as ident
                      from plans p3
                     where lower(p3.model) = lower(b.model)
                    union all
                    select 'o:' || u.id::text as ident
                      from canta_users u
                     where lower(u.model) = lower(b.model)
                ) ids) as model_people
          from builds b
         group by b.brand, b.model
    )
    select b.brand, b.model, coalesce(m.market_name, ''), b.rom, b.rom_version,
           b.plans, b.people, m.model_plans, m.model_people
      from builds b
      join models m on m.brand = b.brand and m.model = b.model
     order by m.model_people desc, b.brand, b.model, b.rom_version desc, b.rom
$$;

revoke all on function public.plan_submit(jsonb) from public;
revoke all on function public.plans_for(text, text, text, integer, integer) from public;
revoke all on function public.plan_get(bigint) from public;
revoke all on function public.plans_by_owner(text) from public;
revoke all on function public.plans_for_model(text, text, text, integer, integer) from public;
revoke all on function public.plan_catalog() from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_submit(jsonb) to anon;
        grant execute on function public.plans_for(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_get(bigint) to anon;
        grant execute on function public.plans_by_owner(text) to anon;
        grant execute on function public.plans_for_model(text, text, text, integer, integer) to anon;
        grant execute on function public.plan_catalog() to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_submit(jsonb) to authenticated;
        grant execute on function public.plans_for(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_get(bigint) to authenticated;
        grant execute on function public.plans_by_owner(text) to authenticated;
        grant execute on function public.plans_for_model(text, text, text, integer, integer) to authenticated;
        grant execute on function public.plan_catalog() to authenticated;
    end if;
end $$;
