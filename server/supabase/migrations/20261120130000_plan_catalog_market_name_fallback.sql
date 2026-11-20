-- Name the model even when the plan that introduced it was uploaded without a market name.
--
-- 20261119230000 already lends a name from the comments: `private.model_names` pairs a retail number
-- with the name a commenter's phone showed. That only works when the commenter's identity row still
-- carries the same retail number — an identity whose `model` was recorded some other way (an older
-- build, a re-login on a different ROM) teaches nothing, and the chips keep showing "M2006J10C".
--
-- Two more sources are added, in this order:
--   1. a plan of the same model string that has a name (what the catalog always did);
--   2. `private.model_names` (what 20261119230000 added);
--   3. a plan of the same *codename* that has a name — the ROM's own name for the phone. A codename
--      is unique per model, so this only ever lends a name between rows of the same phone.
--
-- Run after 20261120120000_package_vote_model_scope.sql.

create or replace function public.plan_catalog() returns table (
    brand text, model text, market_name text, rom text, rom_version integer,
    plans bigint, people bigint, model_plans bigint, model_people bigint
) language sql stable security definer set search_path = public, private as $$
    with builds as (
        select coalesce(nullif(p.brand, ''), 'unknown') as brand,
               p.model,
               min(coalesce(p.codename, '')) as codename,
               p.rom,
               p.rom_version,
               count(*)::bigint as plans,
               count(distinct case
                        when coalesce(p.owner, '') <> '' then 'o:' || p.owner
                        else 'r:' || p.reporter
                      end)::bigint as people
          from plans p
         where coalesce(p.model, '') <> ''
         group by 1, 2, 4, 5
    ), codenames as (
        -- One codename per model string: the last fallback below needs it, the counts do not.
        select b.brand, b.model, min(nullif(b.codename, '')) as codename
          from builds b
         group by 1, 2
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
                   -- Still nothing: lend it from another build of the same codename, i.e. the same
                   -- phone under the ROM's own name for it.
                   (select coalesce(p4.market_name, '')
                      from plans p4
                     where coalesce(cn.codename, '') <> ''
                       and lower(p4.codename) = lower(cn.codename)
                       and coalesce(p4.market_name, '') <> ''
                     order by p4.created_at desc
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
          join codenames cn on cn.brand = b.brand and cn.model = b.model
         group by b.brand, b.model, cn.codename
    )
    select b.brand, b.model, coalesce(m.market_name, ''), b.rom, b.rom_version,
           b.plans, b.people, m.model_plans, m.model_people
      from builds b
      join models m on m.brand = b.brand and m.model = b.model
     order by m.model_people desc, b.brand, b.model, b.rom_version desc, b.rom
$$;

grant execute on function public.plan_catalog() to anon, authenticated;
