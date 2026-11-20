-- Add system-family vote counts while preserving the existing device and all-device fields.
-- Run after 20261119140000_comment_identity_and_vote_scope.sql.

create or replace function public.package_vote_counts(
    p_pkg text, p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0
) returns jsonb language sql stable security definer set search_path = public as $$
    with scoped as (
        select v.can_remove, v.model, v.codename, v.rom, v.rom_version
        from package_votes v
        where v.pkg = p_pkg
    ), device as (
        select can_remove from scoped
        where coalesce(p_model, '') = ''
           or (
               lower(model) = lower(coalesce(p_model, ''))
               and rom = coalesce(p_rom, '')
               and rom_version = coalesce(p_rom_version, 0)
               and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
           )
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
        from scoped
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
