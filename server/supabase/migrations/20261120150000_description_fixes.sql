-- Community-corrected descriptions: the bloat list's one line about what an app is, rewritten by
-- the people who actually run it, and voted on until it can stand in for the published line.
--
-- The published description comes from the bloat list, which is written once, in English, and often
-- describes a version of the app two ROMs old. The app page is the one place where the right reader
-- is standing: they have the package installed and they know what it does on their phone. So the
-- page gains a second, voted-on description:
--
--   * `description_fixes`        one proposed rewrite per package. `applied` marks the one the
--                               community accepted; the app shows it in place of the published text.
--   * `description_fix_votes`    one vote per (fix, identity): 赞同 / 不赞同. Tapping the same side
--                               twice leaves one vote, tapping the other side changes it.
--   * `description_fix_add`      files a rewrite. One pending rewrite per identity and package: the
--                               second one edits the first instead of stacking up.
--   * `description_fix_vote`     votes, then re-settles the package, answering the fresh counts.
--   * `description_fixes_for`    the history: every rewrite of a package with its counts and how
--                               this caller voted, accepted one first.
--   * `description_fix_current`  just the accepted rewrite, for the page that only shows a line.
--
-- The rule is fixed at 50 agreeing votes and an 80% share: `private.description_fix_settle` picks the
-- rewrite that satisfies both and clears `applied` on everything else, so a package never shows two
-- accepted rewrites and never keeps one after its support fell (votes can be changed, and a rewrite
-- that dropped under the bar loses the mark again).
--
-- Run after 20261120140000_comment_inbox.sql (or use server/supabase/apply-all.sql).

create table if not exists public.description_fixes (
    id         bigserial primary key,
    -- The package this rewrite is about; 200 chars is the longest a real package name gets.
    pkg        text not null,
    -- The rewrite itself, and the optional "what was wrong with the old line" note beside it.
    body       text not null,
    note       text not null default '',
    -- Who wrote it: the display name it was signed with, and the identity number behind it.
    author     text not null default '',
    author_id  text not null default '',
    -- True for the one rewrite the community accepted: the app shows this body instead.
    applied    boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- The page asks for one package's rewrites, accepted one first; the vote count is computed from the
-- vote table, so this index only has to make the package lookup cheap.
create index if not exists description_fixes_pkg_idx
    on public.description_fixes (pkg, applied desc, created_at desc);

create table if not exists public.description_fix_votes (
    fix_id     bigint not null references public.description_fixes (id) on delete cascade,
    -- The identity number (or its token fallback) that voted: one vote per rewrite.
    voter      text not null,
    -- true: 认同这条修正. false: 不认同.
    agree      boolean not null,
    created_at timestamptz not null default now(),
    primary key (fix_id, voter)
);

create index if not exists description_fix_votes_fix_idx on public.description_fix_votes (fix_id);

-- Rows are only ever read and written through the functions below (security definer), so the tables
-- themselves grant nothing to the API roles.
alter table public.description_fixes enable row level security;
alter table public.description_fix_votes enable row level security;

-- ---------------------------------------------------------------- the rule

/** Agreeing votes a rewrite needs before it can replace the published description. */
create or replace function private.description_fix_votes_needed() returns int
language sql immutable set search_path = ''
as $$ select 50 $$;

/** Share of those votes that has to agree: 50/62 clears it, 50/63 does not. */
create or replace function private.description_fix_share_needed() returns numeric
language sql immutable set search_path = ''
as $$ select 0.80::numeric $$;

/**
 * Marks the rewrite of [p_pkg] that currently satisfies the rule as `applied`, and takes the mark
 * off every other rewrite of that package.
 *
 * Called after every add and every vote, so the mark always matches the counts stored beside it.
 * The winner is the one with most agreeing votes, ties going to the older rewrite: two rewrites that
 * both qualify must not both be shown, and the one the community backed first deserves the mark.
 */
create or replace function private.description_fix_settle(p_pkg text)
returns void language plpgsql security definer set search_path = public as $$
declare
    winner bigint;
begin
    select t.fix_id into winner
    from (
        select f.id as fix_id,
               f.created_at,
               count(*) filter (where v.agree) as agrees,
               count(*) filter (where not v.agree) as disagrees
        from description_fixes f
        left join description_fix_votes v on v.fix_id = f.id
        where f.pkg = p_pkg
        group by f.id, f.created_at
    ) t
    where t.agrees >= private.description_fix_votes_needed()
      and t.agrees >= private.description_fix_share_needed() * greatest(t.agrees + t.disagrees, 1)
    order by t.agrees desc, t.created_at asc
    limit 1;

    update description_fixes
       set applied = (id = coalesce(winner, -1))
     where pkg = p_pkg
       and applied <> (id = coalesce(winner, -1));
end;
$$;

-- ---------------------------------------------------------------- writing

/**
 * Files [p_body] as a description rewrite for [p_pkg], replacing the pending rewrite this identity
 * already filed on the same package.
 *
 * One pending rewrite per identity and package: writing again is editing what was written, not
 * starting a second entry that says the same thing. A rewrite that already took effect is not
 * touched — a reader who wants to change an accepted line files a new one.
 *
 * Answers `{id}` when the rewrite was stored, null when there was nothing to store (no package, no
 * text).
 */
create or replace function public.description_fix_add(
    p_pkg text,
    p_body text,
    p_note text default '',
    p_author text default '',
    p_author_id text default ''
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
    pkg_text text := left(btrim(coalesce(p_pkg, '')), 200);
    body_text text := left(btrim(coalesce(p_body, '')), 4000);
    note_text text := left(btrim(coalesce(p_note, '')), 300);
    author_text text := left(btrim(coalesce(p_author, '')), 60);
    author_id_text text := left(btrim(coalesce(p_author_id, '')), 60);
    existing bigint;
    new_id bigint;
begin
    if pkg_text = '' or body_text = '' then
        return null;
    end if;

    if author_id_text <> '' then
        select f.id into existing
        from description_fixes f
        where f.pkg = pkg_text
          and f.author_id = author_id_text
          and not f.applied
        order by f.created_at desc
        limit 1;
    end if;

    if existing is not null then
        update description_fixes
           set body = body_text,
               note = note_text,
               author = author_text,
               updated_at = now()
         where id = existing;
        perform private.description_fix_settle(pkg_text);
        return jsonb_build_object('id', existing);
    end if;

    insert into description_fixes (pkg, body, note, author, author_id)
    values (pkg_text, body_text, note_text, author_text, author_id_text)
    returning id into new_id;

    perform private.description_fix_settle(pkg_text);
    return jsonb_build_object('id', new_id);
end;
$$;

/**
 * Votes on rewrite [p_id]: [p_agree] true is 认同, false is 不认同, and both are safe to repeat —
 * the pair is the primary key, so tapping twice leaves one vote and tapping the other side changes
 * it. The package is re-settled afterwards, which is what can promote this rewrite to `applied`.
 *
 * Answers `{agrees, disagrees, applied}` with the counts after the vote, so the page never has to
 * guess what the server thinks. Answers null when the rewrite is gone or nobody is voting.
 */
create or replace function public.description_fix_vote(p_id bigint, p_voter text, p_agree boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
    voter_text text := left(btrim(coalesce(p_voter, '')), 60);
    fix_pkg text;
    yes_count bigint;
    no_count bigint;
    is_applied boolean;
begin
    if p_id is null or voter_text = '' then
        return null;
    end if;

    select f.pkg into fix_pkg from description_fixes f where f.id = p_id;
    if not found then
        return null;
    end if;

    insert into description_fix_votes (fix_id, voter, agree)
    values (p_id, voter_text, coalesce(p_agree, true))
    on conflict (fix_id, voter) do update
        set agree = excluded.agree,
            created_at = now();

    perform private.description_fix_settle(fix_pkg);

    select count(*) filter (where agree), count(*) filter (where not agree)
      into yes_count, no_count
      from description_fix_votes
     where fix_id = p_id;

    select applied into is_applied from description_fixes where id = p_id;

    return jsonb_build_object(
        'agrees', yes_count,
        'disagrees', no_count,
        'applied', coalesce(is_applied, false)
    );
end;
$$;

-- ---------------------------------------------------------------- reading

/**
 * Every rewrite of [p_pkg], the accepted one first and then the best supported.
 *
 * Each row carries its own counts, how [p_voter] voted (`mine`, null while it did not), and the rule
 * that applies to it (`needed`, `share`) — the page can show "还差 12 票 · 认同 71%" without knowing
 * the numbers itself.
 */
create or replace function public.description_fixes_for(p_pkg text, p_voter text default '')
returns jsonb language sql stable security definer set search_path = public as $$
    select coalesce(jsonb_agg(
        jsonb_build_object(
            'id', r.id,
            'body', r.body,
            'note', r.note,
            'author', r.author,
            'author_id', r.author_id,
            'created_at', r.created_at,
            'applied', r.applied,
            'agrees', r.agrees,
            'disagrees', r.disagrees,
            'mine', r.mine,
            'needed', private.description_fix_votes_needed(),
            'share', private.description_fix_share_needed()
        )
        order by r.applied desc, r.agrees desc, r.created_at desc
    ), '[]'::jsonb)
    from (
        select f.id, f.body, f.note, f.author, f.author_id, f.created_at, f.applied,
               coalesce(v.agrees, 0) as agrees,
               coalesce(v.disagrees, 0) as disagrees,
               v.mine
        from description_fixes f
        left join lateral (
            select count(*) filter (where vv.agree) as agrees,
                   count(*) filter (where not vv.agree) as disagrees,
                   (array_agg(vv.agree) filter (
                       where vv.voter = left(coalesce(p_voter, ''), 60)
                   ))[1] as mine
            from description_fix_votes vv
            where vv.fix_id = f.id
        ) v on true
        where f.pkg = left(coalesce(p_pkg, ''), 200)
    ) r
$$;

/** The accepted rewrite of [p_pkg] alone, or null while the published description still stands. */
create or replace function public.description_fix_current(p_pkg text)
returns jsonb language sql stable security definer set search_path = public as $$
    select jsonb_build_object(
        'id', f.id,
        'body', f.body,
        'note', f.note,
        'author', f.author,
        'created_at', f.created_at,
        'agrees', (select count(*) from description_fix_votes v
                    where v.fix_id = f.id and v.agree),
        'disagrees', (select count(*) from description_fix_votes v
                       where v.fix_id = f.id and not v.agree)
    )
    from description_fixes f
    where f.pkg = left(coalesce(p_pkg, ''), 200)
      and f.applied
    order by f.created_at desc
    limit 1
$$;

grant execute on function public.description_fix_add(text, text, text, text, text) to anon, authenticated;
grant execute on function public.description_fix_vote(bigint, text, boolean) to anon, authenticated;
grant execute on function public.description_fixes_for(text, text) to anon, authenticated;
grant execute on function public.description_fix_current(text) to anon, authenticated;
