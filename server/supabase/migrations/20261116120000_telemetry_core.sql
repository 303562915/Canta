-- Anonymous package-safety telemetry: storage.
--
-- Wire-compatible with the client in composeApp (see util/Telemetry.kt and
-- util/Pow.kt): the app posts to /rest/v1/rpc/challenge and /rest/v1/rpc/record
-- and reads /rest/v1/rpc/package_scores and /rest/v1/rpc/package_scores_for.
--
-- Nothing here identifies a device: the payload carries only brand, ROM family,
-- ROM major version and API level, and the raw events are dropped after the
-- retention window (see the purge function).

create table if not exists public.telemetry_challenges (
    challenge  text primary key,
    sig        text not null,
    created_at timestamptz not null default now(),
    used_at    timestamptz
);

comment on table public.telemetry_challenges is
    'One row per proof-of-work challenge handed out; used_at makes each usable once.';

create index if not exists telemetry_challenges_created_idx
    on public.telemetry_challenges (created_at);

create table if not exists public.telemetry_events (
    id          bigserial primary key,
    received_at timestamptz not null default now(),
    -- 'android', 'desktop' or 'web' (the client's platform label)
    platform    text not null,
    pkg         text not null,
    kind        text not null,
    cohort_week date not null,
    batch_bucket text not null,
    brand       text not null,
    rom         text not null,
    rom_version integer not null,
    sdk         integer not null,
    constraint telemetry_events_kind_valid check (
        kind in ('uninstalled', 'survived_reboot', 'reinstalled', 'voided', 'restored')
    ),
    constraint telemetry_events_bucket_valid check (batch_bucket in ('1', '2-10', '11+'))
);

comment on table public.telemetry_events is
    'Raw anonymous events; wiped by purge_raw_events() after the retention window.';
comment on column public.telemetry_events.kind is
    'uninstalled / survived_reboot / reinstalled / voided / restored (the last one: put back by hand).';

create index if not exists telemetry_events_pkg_idx on public.telemetry_events (pkg);
create index if not exists telemetry_events_pkg_rom_idx on public.telemetry_events (pkg, rom, rom_version);
create index if not exists telemetry_events_received_idx on public.telemetry_events (received_at);

-- The tables are only reachable through the RPC functions below.
alter table public.telemetry_challenges enable row level security;
alter table public.telemetry_events enable row level security;

-- No policies on purpose: anon and authenticated get nothing from the tables.

-- Aggregated scores. Recomputed on read (there is not enough data for that to
-- matter yet); replace with a materialized view if the tables grow.
create or replace view public.telemetry_package_aggregate as
select
    pkg,
    rom,
    rom_version,
    count(*) filter (where kind = 'uninstalled')                    as uninstalls,
    count(*) filter (where kind = 'survived_reboot')                 as survived,
    count(*) filter (where kind = 'reinstalled')                     as reinstalled,
    count(*) filter (where kind = 'restored')                        as restored,
    count(*) filter (where kind = 'uninstalled' and batch_bucket <> '11+') as small_batch_uninstalls,
    max(received_at)                                                 as updated_at
from public.telemetry_events
group by pkg, rom, rom_version;
