-- Names for the models whose ROM never reports one.
--
-- The catalog chip prefers the model's marketing name and falls back to the retail number the ROM
-- reports ("SM-F9710", "PHK110", "V2337A"). Until now a name could only arrive from a phone: the
-- uploader's `market_name` (read from a `*market.name*` property) or a commenter's `device_model`.
-- Two classes of phone never deliver either:
--
--   * Samsung on One UI — the retail code sits in `ro.product.model`, and the name ("Galaxy Z Fold8")
--     is not a property at all, so nothing on the device can be read.
--   * a vendored ROM that hides its market-name property from an ordinary `getprop` read.
--
-- The client now reads the vivo / OPPO / OnePlus keys as well (util/DeviceContext.kt), which lets
-- those phones heal themselves on the next upload. Samsung cannot, so the catalog needs a place for
-- names that are *data* rather than code:
--
--   private.device_names  = retail number -> marketing name, curated here or by hand in SQL
--
-- `plan_catalog` consults it after the plans' own names and the comment-learned pairs, and before
-- lending a name from another build of the same codename. Rows can be added later without an app
-- release — which is the point: a phone nobody can read a name off can still be named once somebody
-- writes the pair down.
--
-- Run after 20261121140000_inbox_seen_by_kind.sql (or use server/supabase/apply-all.sql).

create schema if not exists private;

/** Curated retail number -> marketing name. Matching is on `lower(model)`; one name per number. */
create table if not exists private.device_names (
    model       text primary key,
    market_name text not null,
    source      text not null default 'manual',
    updated_at  timestamptz not null default now()
);

comment on table private.device_names is
    'Retail model number -> marketing name for devices whose ROM reports no name; consulted by plan_catalog.';

-- The four models the community has already uploaded that no property names. Retail numbers are
-- case-insensitive, so they are stored lowercased.
insert into private.device_names (model, market_name, source) values
    ('sm-f9710', 'Galaxy Z Fold8',       'samsung-model-number'),
    ('sm-f9760', 'Galaxy Z Fold8 Ultra', 'samsung-model-number'),
    ('phk110',   '一加 Ace 2',            'oppo-model-number'),
    ('v2337a',   'vivo X Fold3 Pro',      'vivo-model-number')
on conflict (model) do update
    set market_name = excluded.market_name,
        source      = excluded.source,
        updated_at  = now();

-- Backfill once: rows uploaded before the table existed get the name too. Existing values stay.
update plans p
   set market_name = d.market_name
  from private.device_names d
 where coalesce(p.market_name, '') = ''
   and lower(p.model) = d.model;

/**
 * The catalog with the seeded names added as a third source. Everything else is unchanged from
 * 20261120130000: the plans' own names win, then the comment-learned pairs, then the seed table,
 * then a name lent from another build of the same codename.
 */
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
                   -- Neither: the number is named here, in data, because its ROM reports no name.
                   (select d.market_name
                      from private.device_names d
                     where d.model = lower(b.model)
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

revoke all on function public.plan_catalog() from public;

grant execute on function public.plan_catalog() to anon, authenticated;