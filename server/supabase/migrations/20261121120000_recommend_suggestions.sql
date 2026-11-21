-- Community recommendations: the other half of the recommendations page — an app anybody may put
-- up, voted on until the community agrees it belongs.
--
-- The shipped catalog is a JSON file written by the maintainers: it is a good list and a closed
-- one. This is the open one. Anybody can propose an app, on two conditions that are the whole
-- point of the page — it is open source, and it lives on GitHub — and everybody else votes:
--
--   * `recommend_suggestions`       one proposed app: name, the GitHub project page, the category it
--                                   would sit under, one sentence, the licence it is under, and who
--                                   filed it. `applied` marks the entry the community accepted.
--   * `recommend_suggestion_votes`  one vote per (entry, identity): 认同 / 不认同. Tapping the same
--                                   side twice leaves one vote, tapping the other side changes it.
--   * `recommend_suggestion_add`    files an entry. One pending entry per identity and project: the
--                                   second one edits the first instead of stacking up.
--   * `recommend_suggestion_vote`   votes, then re-settles the project, answering the fresh counts.
--   * `recommend_suggestions`       every entry with its counts and how this caller voted, accepted
--                                   ones first.
--
-- The rule is the one the description corrections already use, read the way the page states it: 50
-- votes in all, of which 80% have to agree — forty of fifty clears it, forty of fifty-one does not.
-- `private.recommend_settle` picks, per project, the entry that satisfies both and clears `applied`
-- on the others, so one project never shows two accepted entries and never keeps the mark after its
-- support fell — votes can be changed, and an entry that dropped under the bar loses the mark again.
--
-- Run after 20261120190000_plan_device_coverage.sql (or use server/supabase/apply-all.sql).

create schema if not exists private;

create table if not exists public.recommend_suggestions (
    id         bigserial primary key,
    -- What the app is called, the way the catalog names its entries.
    name       text not null,
    -- The GitHub project page; the only kind of link this list accepts.
    url        text not null,
    -- One of the six catalog categories; anything else is filed under tools.
    category   text not null default 'tools',
    -- One sentence on why it is worth the space, and the licence it is under.
    summary    text not null default '',
    license    text not null default '',
    -- Who filed it: the display name it was signed with, and the identity number behind it.
    author     text not null default '',
    author_id  text not null default '',
    -- True for the entry the community accepted: the page shows it as one of its own.
    applied    boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- The page reads the whole list in one go and sorts it by project; the counts come from the vote
-- table, so this index only has to make the project lookup cheap.
create index if not exists recommend_suggestions_url_idx
    on public.recommend_suggestions (lower(btrim(url)), applied desc, created_at desc);

create table if not exists public.recommend_suggestion_votes (
    suggestion_id bigint not null references public.recommend_suggestions (id) on delete cascade,
    -- The identity number (or its token fallback) that voted: one vote per entry.
    voter         text not null,
    -- true: 认同这个应用该进列表. false: 不认同.
    agree         boolean not null,
    created_at    timestamptz not null default now(),
    primary key (suggestion_id, voter)
);

create index if not exists recommend_suggestion_votes_entry_idx
    on public.recommend_suggestion_votes (suggestion_id);

-- Rows are only ever read and written through the functions below (security definer), so the tables
-- themselves grant nothing to the API roles.
alter table public.recommend_suggestions enable row level security;
alter table public.recommend_suggestion_votes enable row level security;

-- ---------------------------------------------------------------- the rule

/** Votes an entry needs before it can join the page, both sides counted. */
create or replace function private.recommend_votes_needed() returns int
language sql immutable set search_path = ''
as $$ select 50 $$;

/** Share of all votes that has to agree: 40 of 50 clears it, 40 of 51 does not. */
create or replace function private.recommend_share_needed() returns numeric
language sql immutable set search_path = ''
as $$ select 0.80::numeric $$;

/**
 * Marks the entry for project [p_url] that currently satisfies the rule as `applied`, and takes
 * the mark off every other entry for the same project.
 *
 * Matching is on the project, not on the entry: two people proposing the same app are proposing
 * the same app, and the page must not list it twice because both cleared the bar. The winner is
 * the one with most agreeing votes, ties going to the older entry.
 */
create or replace function private.recommend_settle(p_url text)
returns void language plpgsql security definer set search_path = public as $$
declare
    project text := lower(btrim(coalesce(p_url, '')));
    winner  bigint;
begin
    select t.id into winner
    from (
        select s.id,
               s.created_at,
               count(*) filter (where v.agree) as agrees,
               count(*) filter (where not v.agree) as disagrees
        from recommend_suggestions s
        left join recommend_suggestion_votes v on v.suggestion_id = s.id
        where lower(btrim(s.url)) = project
        group by s.id, s.created_at
    ) t
    where t.agrees + t.disagrees >= private.recommend_votes_needed()
      and t.agrees >= private.recommend_share_needed() * greatest(t.agrees + t.disagrees, 1)
    order by t.agrees desc, t.created_at asc
    limit 1;

    update recommend_suggestions
       set applied = (id = coalesce(winner, -1))
     where lower(btrim(url)) = project
       and applied <> (id = coalesce(winner, -1));
end;
$$;

-- ---------------------------------------------------------------- writing

/**
 * Files [p_name] on [p_url] as a recommendation, replacing the pending entry this identity already
 * filed for the same project.
 *
 * One pending entry per identity and project: filing again is editing what was filed, not starting
 * a second row that says the same thing. An entry that already took effect is not touched — a
 * reader who wants to change an accepted entry files a new one only when it is a different app.
 *
 * The link has to be a GitHub project page; anything else is refused, because "open source, on
 * GitHub" is the only promise this list makes. A category outside the catalog's six is filed under
 * tools rather than rejected: the sentence and the votes are what the entry is judged on.
 *
 * Answers `{id}` when the entry was stored, null when there was nothing to store (no name, no
 * link, no identity to file it under).
 */
create or replace function public.recommend_suggestion_add(
    p_name text,
    p_url text,
    p_summary text default '',
    p_category text default 'tools',
    p_license text default '',
    p_author text default '',
    p_author_id text default ''
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
    name_text     text := left(btrim(coalesce(p_name, '')), 60);
    url_text      text := left(btrim(coalesce(p_url, '')), 300);
    summary_text  text := left(btrim(coalesce(p_summary, '')), 300);
    license_text  text := left(btrim(coalesce(p_license, '')), 40);
    category_text text := lower(btrim(coalesce(p_category, '')));
    author_text   text := left(btrim(coalesce(p_author, '')), 60);
    author_id_text text := left(btrim(coalesce(p_author_id, '')), 60);
    existing      bigint;
    new_id        bigint;
begin
    if name_text = '' or url_text = '' then
        return null;
    end if;

    -- Exactly the shape the client's `githubProjectUrl` produces: the project root of a GitHub
    -- page, nothing deeper and nothing before it. The guard is strict on purpose — a link that the
    -- form would refuse must not be storable by posting the RPC directly.
    if url_text !~* '^https://(www\.)?github\.com/[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+$' then
        raise exception 'recommendation must link a GitHub project' using errcode = '22023';
    end if;
    if (regexp_match(url_text, '^https://(www\.)?github\.com/[^/]+/([^/?#]+)', 'i'))[2] ~* '\.git\.git$' then
        raise exception 'recommendation must link a GitHub project' using errcode = '22023';
    end if;
    if url_text ~* '^https://(www\.)?github\.com/[^/]+/(\.|\.\.)$' then
        raise exception 'recommendation must link a GitHub project' using errcode = '22023';
    end if;

    if category_text not in ('system', 'store', 'privacy', 'files', 'media', 'tools') then
        category_text := 'tools';
    end if;

    if author_id_text <> '' then
        select s.id into existing
        from recommend_suggestions s
        where lower(btrim(s.url)) = lower(url_text)
          and s.author_id = author_id_text
          and not s.applied
        order by s.created_at desc
        limit 1;
    end if;

    if existing is not null then
        update recommend_suggestions
           set name = name_text,
               summary = summary_text,
               category = category_text,
               license = license_text,
               author = author_text,
               updated_at = now()
         where id = existing;
        perform private.recommend_settle(url_text);
        return jsonb_build_object('id', existing);
    end if;

    insert into recommend_suggestions (name, url, category, summary, license, author, author_id)
    values (name_text, url_text, category_text, summary_text, license_text, author_text, author_id_text)
    returning id into new_id;

    perform private.recommend_settle(url_text);
    return jsonb_build_object('id', new_id);
end;
$$;

/**
 * Votes on entry [p_id]: [p_agree] true is 认同, false is 不认同, and both are safe to repeat — the
 * pair is the primary key, so tapping twice leaves one vote and tapping the other side changes it.
 * The project is re-settled afterwards, which is what can promote this entry to `applied`.
 *
 * Answers `{agrees, disagrees, applied}` with the counts after the vote, so the page never has to
 * guess what the server thinks. Answers null when the entry is gone or nobody is voting.
 */
create or replace function public.recommend_suggestion_vote(p_id bigint, p_voter text, p_agree boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    voter_text text := left(btrim(coalesce(p_voter, '')), 60);
    entry_url  text;
    yes_count  bigint;
    no_count   bigint;
    is_applied boolean;
begin
    if p_id is null or voter_text = '' then
        return null;
    end if;

    select s.url into entry_url from recommend_suggestions s where s.id = p_id;
    if not found then
        return null;
    end if;

    insert into recommend_suggestion_votes (suggestion_id, voter, agree)
    values (p_id, voter_text, coalesce(p_agree, true))
    on conflict (suggestion_id, voter) do update
        set agree = excluded.agree,
            created_at = now();

    perform private.recommend_settle(entry_url);

    select count(*) filter (where agree), count(*) filter (where not agree)
      into yes_count, no_count
      from recommend_suggestion_votes
     where suggestion_id = p_id;

    select applied into is_applied from recommend_suggestions where id = p_id;

    return jsonb_build_object(
        'agrees', yes_count,
        'disagrees', no_count,
        'applied', coalesce(is_applied, false)
    );
end;
$$;

-- ---------------------------------------------------------------- reading

/**
 * Every proposed app, the accepted ones first and then the best supported.
 *
 * Each row carries its own counts, how [p_voter] voted (`mine`, null while it did not), and the rule
 * that applies to it (`needed`, `share`) — the page can show "还差 12 票 · 认同 71%" without knowing
 * the numbers itself. The list is capped at 120 entries: a queue nobody scrolls past the first
 * screen of is not worth a heavier answer.
 */
create or replace function public.recommend_suggestions(p_voter text default '')
returns jsonb language sql stable security definer set search_path = public as $$
    select coalesce(jsonb_agg(
        jsonb_build_object(
            'id', r.id,
            'name', r.name,
            'url', r.url,
            'category', r.category,
            'summary', r.summary,
            'license', r.license,
            'author', r.author,
            'author_id', r.author_id,
            'created_at', r.created_at,
            'applied', r.applied,
            'agrees', r.agrees,
            'disagrees', r.disagrees,
            'mine', r.mine,
            'needed', private.recommend_votes_needed(),
            'share', private.recommend_share_needed()
        )
        order by r.applied desc, r.agrees desc, r.created_at desc
    ), '[]'::jsonb)
    from (
        select s.id, s.name, s.url, s.category, s.summary, s.license, s.author, s.author_id,
               s.created_at, s.applied,
               coalesce(v.agrees, 0) as agrees,
               coalesce(v.disagrees, 0) as disagrees,
               v.mine
        from recommend_suggestions s
        left join lateral (
            select count(*) filter (where vv.agree) as agrees,
                   count(*) filter (where not vv.agree) as disagrees,
                   (array_agg(vv.agree) filter (
                       where vv.voter = left(coalesce(p_voter, ''), 60)
                   ))[1] as mine
            from recommend_suggestion_votes vv
            where vv.suggestion_id = s.id
        ) v on true
        order by s.applied desc, coalesce(v.agrees, 0) desc, s.created_at desc
        limit 120
    ) r
$$;

grant execute on function public.recommend_suggestion_add(text, text, text, text, text, text, text)
    to anon, authenticated;
grant execute on function public.recommend_suggestion_vote(bigint, text, boolean) to anon, authenticated;
grant execute on function public.recommend_suggestions(text) to anon, authenticated;

notify pgrst, 'reload schema';