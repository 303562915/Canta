-- Keep the "system version" breakdown on this phone's own model.
--
-- 20261120110000 counted `systems` over every vote the package ever got, so a Redmi K70 page
-- offered another phone's build (a Redmi K30 Ultra's MIUI, say) as if this phone had run it.
-- The breakdown now comes only from votes cast on the caller's model (and codename when it is
-- known); votes from other phones still land in `all_yes` / `all_no` — they just no longer name
-- a system under this phone.
--
-- Run after 20261120110000_package_vote_system_scope.sql.

create or replace function public.package_vote_counts(
    p_pkg text, p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0
) returns jsonb language sql stable security definer set search_path = public as $$
    with scoped as (
        select v.can_remove, v.model, v.codename, v.rom, v.rom_version
        from package_votes v
        where v.pkg = p_pkg
    ), this_model as (
        -- An empty [p_model] means the caller could not name its phone yet: there is no model to
        -- narrow to, so the scope stays the whole table instead of a zero that reads like
        -- "nobody voted".
        select * from scoped
        where coalesce(p_model, '') = ''
           or (
               lower(model) = lower(coalesce(p_model, ''))
               and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
           )
    ), device as (
        -- "This phone" is still model + ROM + ROM version: a different build of the same model is
        -- context for the reader, not a verdict on their own build.
        select can_remove from this_model
        where coalesce(p_model, '') = ''
           or (rom = coalesce(p_rom, '') and rom_version = coalesce(p_rom_version, 0))
    ), systems as (
        select case rom
                   when 'hyperos' then 'HyperOS'
                   when 'miui' then 'MIUI'
                   when 'oneui' then 'One UI'
                   when 'coloros' then 'ColorOS'
                   when 'realmeui' then 'realme UI'
                   when 'originos' then 'OriginOS'
                   when 'funtouch' then 'Funtouch OS'
                   when 'magicos' then 'MagicOS'
                   when 'emui' then 'EMUI'
                   when 'oxygenos' then 'OxygenOS'
                   when 'nothingos' then 'Nothing OS'
                   else 'Android'
               end || case when rom_version > 0 and rom not in ('', 'android')
                           then ' ' || rom_version else '' end as label,
               count(*) filter (where can_remove) as yes,
               count(*) filter (where not can_remove) as no
        from this_model
        group by 1
    )
    select jsonb_build_object(
        'yes', (select count(*) from device where can_remove),
        'no', (select count(*) from device where not can_remove),
        'all_yes', (select count(*) from scoped where can_remove),
        'all_no', (select count(*) from scoped where not can_remove),
        'systems', coalesce((
            select jsonb_object_agg(label, jsonb_build_object('yes', yes, 'no', no))
            from systems
        ), '{}'::jsonb)
    )
$$;

grant execute on function public.package_vote_counts(text, text, text, text, integer) to anon, authenticated;
