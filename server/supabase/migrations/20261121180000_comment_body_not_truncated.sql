-- 评论不再按字数截断。
--
-- `comment_add` 与 `plan_comment` 写进来时都套着 `left(p_body, 1000)`：一条 1200 字的评论到服务
-- 器只剩前 1000 字，客户端那边以前也照着同一个数字把输入框砍断，所以读到结尾时少了一截却没人
-- 说过。客户端已经放开（输入框不再截断、也不再显示"还能写 N 字"），这里把服务端的那一刀去掉。
--
-- `community_comments.body` 本来就是 text，Postgres 不限制它的长度；作者名、机型这些短字段的
-- `left()` 保留不动，它们不是这次的事。

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
            left(coalesce(p_author_id, ''), 60), p_body,
            left(coalesce(p_model, ''), 80), left(coalesce(p_system, ''), 60))
    returning id into new_id;
    return new_id;
end;
$$;

-- 老客户端的入口：只认 `plan_comment` 的安装照样能发，同样不再截断。
create or replace function public.plan_comment(p_id bigint, p_body text, p_author text default '') returns bigint
language plpgsql security definer set search_path = public as $$
declare new_id bigint;
begin
    if length(coalesce(p_body, '')) = 0 then
        raise exception 'empty comment' using errcode = '22023';
    end if;
    insert into community_comments (kind, target, author, author_id, body)
    values ('plan', p_id::text, left(coalesce(p_author, ''), 60), left(coalesce(p_author, ''), 60),
            p_body)
    returning id into new_id;
    return new_id;
end;
$$;
