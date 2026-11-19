-- Marketing names for the models the community already talks about.
--
-- The catalog chips prefer the model's marketing name ("Redmi K70"); the fallback is the retail
-- model number the ROM reports ("23113RKC6C"), which is exactly what a visitor cannot read. The
-- `market_name` column is new, so every plan uploaded before it existed has none — and on
-- MIUI/HyperOS the retail number is the only thing those rows carry.
--
-- The names are already in the database, one hop away: comments have always stored the writer's
-- phone as *displayed* (`device_model`), and every comment is signed with the identity number
-- (`author_id`) whose `canta_users.model` is the retail number of the same phone. Pairing those two
-- turns "who wrote this comment" into "this retail number is called this":
--
--   canta_users.model (23113RKC6C)  <->  community_comments.device_model (Redmi K70)
--
-- Two uses:
--   1. a one-time backfill of `plans.market_name` where it is empty;
--   2. a live fallback inside `plan_catalog`, so a model with no named plan but with named
--      commenters still reads like a phone, not a part number.
--
-- Run after 20261119220000_device_catalog.sql (or use server/supabase/apply-all.sql).

/** Comment-derived "retail number -> marketing name" pairs, best pair decided by the caller. */
create or replace view private.model_names as
    select lower(u.model)                        as model,
           c.device_model                        as market_name,
           count(*)::bigint                      as votes
      from community_comments c
      join canta_users u on u.id::text = c.author_id
     where coalesce(c.device_model, '') <> ''
       and coalesce(u.model, '') <> ''
       and lower(c.device_model) <> lower(u.model)
     group by 1, 2;

comment on view private.model_names is
    'Pairs of retail model numbers and the names commenters'' phones showed; votes ranks them.';

-- Backfill once: every plan whose model has a known name gets it. Existing (non-empty) values stay
-- untouched, and re-running is harmless.
with best as (
    select distinct on (model) model, market_name
      from private.model_names
     order by model, votes desc
)
update plans p
   set market_name = best.market_name
  from best
 where coalesce(p.market_name, '') = ''
   and lower(p.model) = best.model;

/**
 * The catalog again, with one change: the model's display name now falls back to the names its
 * commenters' phones reported, not straight to the retail number. Shape is unchanged, so the
 * function is replaced in place.
 */
create or replace function public.plan_catalog() returns table (
    brand text, model text, market_name text, rom text, rom_version integer,
    plans bigint, people bigint, model_plans bigint, model_people bigint
) language sql stable security definer set search_path = public, private as $$
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
               coalesce(
                   (select coalesce(p2.market_name, '')
                      from plans p2
                     where lower(p2.model) = lower(b.model)
                       and coalesce(p2.market_name, '') <> ''
                     order by p2.created_at desc
                     limit 1),
                   -- No plan on this model carries a name, but somebody who owns the phone left a
                   -- comment: their phone said what it is called.
                   (select m.market_name
                      from private.model_names m
                     where m.model = lower(b.model)
                     order by m.votes desc
                     limit 1),
                   ''
               ) as market_name,
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

revoke all on function public.plan_catalog() from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_catalog() to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_catalog() to authenticated;
    end if;
end $$;
