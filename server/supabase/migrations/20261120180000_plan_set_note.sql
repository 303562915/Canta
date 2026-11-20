-- 作者改自己方案的说明。
--
-- 说明（`plans.note`）是方案里唯一能"事后补一句"的地方：哪些包在这台机器上其实不能删、
-- 重启之后要等多久、桌面图标怎么找回来。这些是上传时还不知道、用了一周才写出来的东西，
-- 但在此之前作者只能删掉重传，把赞和评论一起丢掉。
--
-- 只改 note，不动 title、packages 和重启验证的结论：那些是上传那一刻的事实，
-- 事后改包名等于换了一份方案，应该重传。同一套身份证明：号码 + 那把秘密，
-- 光有号码改不动别人的方案。
--
-- Run after 20261120160000_inbox_seen_cursor.sql (or use server/supabase/apply-all.sql).

create or replace function public.plan_set_note(p_id bigint, p_owner text, p_token text, p_note text)
returns boolean
language plpgsql security definer set search_path = public as $$
declare
    changed integer;
begin
    if coalesce(p_owner, '') = '' or coalesce(p_token, '') = '' then
        return false;
    end if;
    -- The token is the proof: a number alone is public information (it is printed beside every comment).
    if not exists (select 1 from canta_users u where u.id::text = p_owner and u.token = p_token) then
        return false;
    end if;
    update plans set note = left(coalesce(p_note, ''), 2000)
     where id = p_id and owner = p_owner;
    get diagnostics changed = row_count;
    return changed > 0;
end;
$$;

revoke all on function public.plan_set_note(bigint, text, text, text) from public;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        grant execute on function public.plan_set_note(bigint, text, text, text) to anon;
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        grant execute on function public.plan_set_note(bigint, text, text, text) to authenticated;
    end if;
end $$;