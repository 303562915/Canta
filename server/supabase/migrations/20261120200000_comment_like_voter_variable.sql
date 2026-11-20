-- A heart on a comment never reached the database.
--
-- `comment_like` declared its local variable as `voter` — the same name as the column the function
-- writes. PL/pgSQL refuses to guess between a variable and a column of the table in scope
-- (`plpgsql.variable_conflict = error`), so every call died with 42702
-- "column reference \"voter\" is ambiguous", the whole function body rolled back, and
-- `comment_likes` stayed empty however many times the heart was tapped. The page kept the tap in
-- memory, which is why a like looked cast until the page was reopened.
--
-- The variable is renamed `v_voter` here, and every reference to it is the variable's own name.
-- `p_voter` is left alone: a parameter never collides with a column, because the two spell
-- differently.

create or replace function public.comment_like(p_id bigint, p_voter text, p_liked boolean)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_voter text := left(coalesce(p_voter, ''), 60);
    writer text;
    total bigint;
begin
    if p_id is null or v_voter = '' then
        return null;
    end if;
    -- Who was hearted is recorded with the heart, so the inbox can report it back later.
    select left(c.author_id, 60) into writer from community_comments c where c.id = p_id;
    if not found then
        return null;
    end if;

    if coalesce(p_liked, false) then
        insert into comment_likes (comment_id, voter, author_id) values (p_id, v_voter, writer)
        on conflict (comment_id, voter) do update set author_id = excluded.author_id;
    else
        delete from comment_likes l where l.comment_id = p_id and l.voter = v_voter;
    end if;

    select count(*) into total from comment_likes l where l.comment_id = p_id;
    return jsonb_build_object(
        'likes', total,
        'liked', exists (select 1 from comment_likes l
                          where l.comment_id = p_id and l.voter = v_voter)
    );
end;
$$;

revoke all on function public.comment_like(bigint, text, boolean) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.comment_like(bigint, text, boolean) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.comment_like(bigint, text, boolean) to authenticated;
    end if;
end $$;
