-- "Can this package be removed?" — a two-sided vote, recorded per package and per device.
--
-- A plan like (`plan_vote`) says "this set of removals was ok on this phone". This table is the
-- other half: every owner can say, for one package, whether *their* phone was fine without it or
-- not. Both sides are counted, because "12 people removed it and nothing broke" and "3 people
-- removed it and it bootlooped" are what tells a reader whether to try it.
--
-- Votes are stored with the device they were cast on, so the app can show "on your model and ROM
-- version" and "on all devices" side by side. One vote per (package, voter): a second vote replaces
-- the first, which is how someone changes their mind.
--
-- Run after 20261119110000_device_identity.sql (or use server/supabase/apply-all.sql).

create table if not exists public.package_votes (
    pkg         text not null,
    -- The install that voted: its identity number, or a per-install id before it has one.
    voter       text not null,
    -- true: the phone was fine without it. false: removing it broke something.
    can_remove  boolean not null,
    -- The device the vote was cast on; empty when it was unknown.
    brand       text not null default '',
    model       text not null default '',
    codename    text not null default '',
    rom         text not null default '',
    rom_version integer not null default 0,
    sdk         integer not null default 0,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    primary key (pkg, voter)
);

create index if not exists package_votes_pkg_idx on public.package_votes (pkg);
create index if not exists package_votes_device_idx on public.package_votes (pkg, model, rom, rom_version);

alter table public.package_votes enable row level security;

/** Counts both sides for [p_pkg], in two scopes: this device, and every device. */
create or replace function public.package_vote_counts(
    p_pkg text, p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0
) returns jsonb language sql stable security definer set search_path = public as $$
    with scoped as (
        select v.can_remove,
               v.model, v.codename, v.rom, v.rom_version
        from package_votes v
        where v.pkg = p_pkg
    ), device as (
        select can_remove from scoped
        where lower(model) = lower(coalesce(p_model, ''))
          and rom = coalesce(p_rom, '')
          and rom_version = coalesce(p_rom_version, 0)
          and (coalesce(p_codename, '') = '' or lower(codename) = lower(p_codename))
    )
    select jsonb_build_object(
        'yes', (select count(*) from device where can_remove),
        'no', (select count(*) from device where not can_remove),
        'all_yes', (select count(*) from scoped where can_remove),
        'all_no', (select count(*) from scoped where not can_remove)
    )
$$;

/**
 * Records what [p_voter] says about [p_pkg] on the device it names, and answers the fresh counts
 * in the same shape as [package_vote_counts].
 *
 * The new vote replaces an earlier one by the same voter, so "I was wrong" is one tap, not a
 * support ticket. An empty voter is rejected: there has to be something to count once.
 */
create or replace function public.package_vote(
    p_pkg text, p_voter text, p_can_remove boolean,
    p_brand text default '', p_model text default '', p_codename text default '',
    p_rom text default '', p_rom_version integer default 0, p_sdk integer default 0
) returns jsonb language plpgsql security definer set search_path = public as $$
begin
    if length(coalesce(p_pkg, '')) = 0 then
        raise exception 'missing package' using errcode = '22023';
    end if;
    if length(coalesce(p_voter, '')) = 0 then
        raise exception 'missing voter' using errcode = '22023';
    end if;

    insert into package_votes (pkg, voter, can_remove, brand, model, codename, rom, rom_version, sdk)
    values (left(p_pkg, 200), left(p_voter, 120), p_can_remove,
            left(coalesce(p_brand, ''), 60), left(coalesce(p_model, ''), 80),
            left(coalesce(p_codename, ''), 80), left(coalesce(p_rom, ''), 60),
            coalesce(p_rom_version, 0), coalesce(p_sdk, 0))
    on conflict (pkg, voter) do update
        set can_remove = excluded.can_remove,
            brand = excluded.brand,
            model = excluded.model,
            codename = excluded.codename,
            rom = excluded.rom,
            rom_version = excluded.rom_version,
            sdk = excluded.sdk,
            updated_at = now();

    return public.package_vote_counts(p_pkg, p_model, p_codename, p_rom, p_rom_version);
end;
$$;

revoke all on function public.package_vote_counts(text, text, text, text, integer) from public;
revoke all on function public.package_vote(text, text, boolean, text, text, text, text, integer, integer) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to anon;
        grant execute on function public.package_vote(text, text, boolean, text, text, text, text, integer, integer) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.package_vote_counts(text, text, text, text, integer) to authenticated;
        grant execute on function public.package_vote(text, text, boolean, text, text, text, text, integer, integer) to authenticated;
    end if;
end $$;
