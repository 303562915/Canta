-- Replies never landed: `comment_add` raised "column reference kind is ambiguous".
--
-- The function kept the requested kind in a variable called `kind` and then compared
-- `c.kind = kind` while selecting from the same table. PL/pgSQL resolves an unqualified name
-- against the query's columns as well as its own variables and refuses to guess, so every call
-- that carried a parent id — that is, every reply — failed before the insert. A comment on its own
-- worked, which is why the thread looked like it had no replies and not like it was broken.
--
-- The variable is `v_kind` now, and the body declares `#variable_conflict use_variable` so a future
-- parameter cannot reintroduce the same trap. Everything else is unchanged.
--
-- Run after 20261119140000_comment_identity_and_vote_scope.sql (or use server/supabase/apply-all.sql).

create or replace function public.comment_add(
    p_kind text, p_target text, p_body text, p_author text default '',
    p_parent bigint default null, p_author_id text default '',
    p_model text default '', p_system text default ''
) returns bigint language plpgsql security definer set search_path = public as $$
#variable_conflict use_variable
declare
    new_id bigint;
    root_id bigint;
    v_kind text := coalesce(nullif(p_kind, ''), 'plan');
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    if length(coalesce(p_target, '')) = 0 then
        raise exception 'missing target' using errcode = '22023';
    end if;

    if p_parent is not null then
        select coalesce(c.parent_id, c.id) into root_id
          from community_comments c
         where c.id = p_parent
           and c.kind = v_kind
           and c.target = p_target;
        if root_id is null then
            raise exception 'parent comment not found' using errcode = '22023';
        end if;
    end if;

    insert into community_comments (kind, target, parent_id, author, author_id, body,
                                   device_model, system_name)
    values (v_kind, left(p_target, 200), root_id, left(coalesce(p_author, ''), 60),
            left(coalesce(p_author_id, ''), 60), left(p_body, 1000),
            left(coalesce(p_model, ''), 80), left(coalesce(p_system, ''), 60))
    returning id into new_id;
    return new_id;
end;
$$;

revoke all on function public.comment_add(text, text, text, text, bigint, text, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comment_add(text, text, text, text, bigint, text, text, text) to authenticated;
    end if;
end $$;
