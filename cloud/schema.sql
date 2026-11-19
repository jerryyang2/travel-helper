-- 旅遊小幫手共用旅程。以登入身分與成員表授權；不開放匿名旅程資料。
begin;
create schema if not exists travel_private;
revoke all on schema travel_private from public;
grant usage on schema travel_private to authenticated;

create table if not exists public.travel_trips (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 100),
  state jsonb not null,
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.travel_trip_members (
  trip_id uuid not null references public.travel_trips(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('editor','viewer')),
  display_name text not null default '旅伴' check (char_length(display_name) between 1 and 80),
  created_at timestamptz not null default now(),
  primary key (trip_id,user_id)
);
create table if not exists public.travel_trip_invites (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.travel_trips(id) on delete cascade,
  token_hash text not null unique,
  role text not null check (role in ('editor','viewer')),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists travel_trip_owner_idx on public.travel_trips(owner_id);
create index if not exists travel_trip_member_user_idx on public.travel_trip_members(user_id,trip_id);
alter table public.travel_trips enable row level security;
alter table public.travel_trip_members enable row level security;
alter table public.travel_trip_invites enable row level security;
revoke all on public.travel_trips,public.travel_trip_members,public.travel_trip_invites from public,anon,authenticated;
grant select on public.travel_trips to authenticated;

create or replace function travel_private.trip_role(p_trip_id uuid) returns text
language sql stable security definer set search_path=''
as $$
 select case when t.owner_id=auth.uid() then 'owner' else m.role end
 from public.travel_trips t left join public.travel_trip_members m
 on m.trip_id=t.id and m.user_id=auth.uid()
 where t.id=p_trip_id and auth.uid() is not null
$$;
revoke all on function travel_private.trip_role(uuid) from public,anon;
grant execute on function travel_private.trip_role(uuid) to authenticated;
drop policy if exists travel_trip_read on public.travel_trips;
create policy travel_trip_read on public.travel_trips for select to authenticated
using (travel_private.trip_role(id) is not null);

create or replace function travel_private.check_state(p_state jsonb) returns void
language plpgsql immutable set search_path=''
as $$
begin
 if p_state is null or jsonb_typeof(p_state) is distinct from 'object'
 or p_state->>'schemaVersion' is distinct from '1'
 or jsonb_typeof(p_state->'config') is distinct from 'object'
 or jsonb_typeof(p_state->'days') is distinct from 'array' then
  raise exception '旅程結構不符' using errcode='22023';
 end if;
 if char_length(coalesce(p_state#>>'{config,name}','')) not between 1 and 100
 or jsonb_array_length(p_state->'days') not between 1 and 30
 or p_state#>>'{config,days}' is distinct from jsonb_array_length(p_state->'days')::text
 or octet_length(p_state::text)>1048576 then
  raise exception '旅程格式不符或超過 1 MB' using errcode='22023';
 end if;
end $$;
revoke all on function travel_private.check_state(jsonb) from public,anon,authenticated;

create or replace function public.list_travel_trips()
returns table(id uuid,title text,revision bigint,updated_at timestamptz,owner_id uuid,role text)
language sql stable security invoker set search_path=''
as $$ select t.id,t.title,t.revision,t.updated_at,t.owner_id,travel_private.trip_role(t.id)
 from public.travel_trips t order by t.updated_at desc $$;

create or replace function public.create_travel_trip(p_id uuid,p_state jsonb) returns jsonb
language plpgsql security definer set search_path=''
as $$
declare v public.travel_trips;
begin
 if auth.uid() is null then raise exception '請先登入' using errcode='42501'; end if;
 perform travel_private.check_state(p_state);
 perform pg_advisory_xact_lock(hashtext(auth.uid()::text));
 select * into v from public.travel_trips where id=p_id;
 if found then
  if v.owner_id<>auth.uid() then raise exception '無法建立旅程' using errcode='42501'; end if;
  return to_jsonb(v)||jsonb_build_object('role','owner');
 end if;
 if (select count(*) from public.travel_trips where owner_id=auth.uid())>=100 then
  raise exception '每個帳號最多 100 趟雲端旅程' using errcode='22023';
 end if;
 insert into public.travel_trips(id,owner_id,title,state)
 values(p_id,auth.uid(),p_state#>>'{config,name}',p_state) returning * into v;
 return to_jsonb(v)||jsonb_build_object('role','owner');
end $$;

create or replace function public.save_travel_trip(p_id uuid,p_state jsonb,p_expected_revision bigint) returns jsonb
language plpgsql security definer set search_path=''
as $$
declare v public.travel_trips; v_role text;
begin
 perform 1 from public.travel_trips where id=p_id for update;
 v_role:=travel_private.trip_role(p_id);
 if auth.uid() is null or v_role is null or v_role not in ('owner','editor') then
  raise exception '沒有編輯權限' using errcode='42501';
 end if;
 perform travel_private.check_state(p_state);
 update public.travel_trips set state=p_state,title=p_state#>>'{config,name}',
 revision=revision+1,updated_at=now() where id=p_id and revision=p_expected_revision returning * into v;
 if not found then
  select * into v from public.travel_trips where id=p_id;
  return jsonb_build_object('ok',false,'conflict',true,'trip',to_jsonb(v)||jsonb_build_object('role',v_role));
 end if;
 return jsonb_build_object('ok',true,'trip',to_jsonb(v)||jsonb_build_object('role',v_role));
end $$;

create or replace function public.create_travel_invite(p_trip_id uuid,p_role text default 'viewer') returns jsonb
language plpgsql security definer set search_path=''
as $$
declare v_token text; v public.travel_trip_invites;
begin
 perform 1 from public.travel_trips where id=p_trip_id for update;
 if coalesce(travel_private.trip_role(p_trip_id),'')<>'owner' then raise exception '只有建立者可邀請' using errcode='42501'; end if;
 if p_role is null or p_role not in ('viewer','editor') then raise exception '權限不符' using errcode='22023'; end if;
 if (select count(*) from public.travel_trip_invites where trip_id=p_trip_id and revoked_at is null and expires_at>now())>=20 then
  raise exception '有效連結已達 20 個，請先撤銷不用的連結' using errcode='22023';
 end if;
 v_token:=replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-','');
 insert into public.travel_trip_invites(trip_id,token_hash,role,expires_at)
 values(p_trip_id,encode(sha256(convert_to(v_token,'UTF8')),'hex'),p_role,now()+interval '7 days') returning * into v;
 return jsonb_build_object('id',v.id,'token',v_token,'role',v.role,'expires_at',v.expires_at);
end $$;

create or replace function public.accept_travel_invite(p_token text,p_display_name text default '旅伴') returns jsonb
language plpgsql security definer set search_path=''
as $$
declare v public.travel_trip_invites; t public.travel_trips; v_role text;
begin
 if auth.uid() is null then raise exception '請先登入再加入' using errcode='42501'; end if;
 if p_token is null or p_token !~ '^[0-9a-f]{64}$' then raise exception '分享連結無效或已到期' using errcode='22023'; end if;
 select * into v from public.travel_trip_invites where token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex') and revoked_at is null and expires_at>now() for share;
 if not found then raise exception '分享連結無效或已到期' using errcode='22023'; end if;
 select * into t from public.travel_trips where id=v.trip_id;
 if t.owner_id<>auth.uid() then
  insert into public.travel_trip_members(trip_id,user_id,role,display_name)
  values(v.trip_id,auth.uid(),v.role,left(coalesce(nullif(trim(p_display_name),''),'旅伴'),80))
  on conflict(trip_id,user_id) do update set
   role=case when public.travel_trip_members.role='editor' then 'editor' else excluded.role end,
   display_name=excluded.display_name;
 end if;
 v_role:=travel_private.trip_role(v.trip_id);
 return to_jsonb(t)||jsonb_build_object('role',v_role);
end $$;

create or replace function public.manage_travel_member(p_trip_id uuid,p_user_id uuid,p_role text default null) returns void
language plpgsql security definer set search_path=''
as $$
begin
 perform 1 from public.travel_trips where id=p_trip_id for update;
 if coalesce(travel_private.trip_role(p_trip_id),'')<>'owner' then raise exception '只有建立者可管理' using errcode='42501'; end if;
 if exists(select 1 from public.travel_trips where id=p_trip_id and owner_id=p_user_id) then raise exception '不能更改建立者權限' using errcode='22023'; end if;
 if p_role is null then delete from public.travel_trip_members where trip_id=p_trip_id and user_id=p_user_id;
 elsif p_role in ('viewer','editor') then update public.travel_trip_members set role=p_role where trip_id=p_trip_id and user_id=p_user_id;
 else raise exception '權限不符' using errcode='22023'; end if;
end $$;

create or replace function public.revoke_travel_invite(p_trip_id uuid,p_invite_id uuid) returns void
language plpgsql security definer set search_path=''
as $$ begin
 perform 1 from public.travel_trips where id=p_trip_id for update;
 if coalesce(travel_private.trip_role(p_trip_id),'')<>'owner' then raise exception '只有建立者可撤銷連結' using errcode='42501'; end if;
 update public.travel_trip_invites set revoked_at=now() where id=p_invite_id and trip_id=p_trip_id;
end $$;

create or replace function public.list_travel_members(p_trip_id uuid)
returns table(user_id uuid,role text,display_name text)
language plpgsql stable security definer set search_path=''
as $$ begin
 if coalesce(travel_private.trip_role(p_trip_id),'')<>'owner' then raise exception '只有建立者可管理' using errcode='42501'; end if;
 return query select m.user_id,m.role,m.display_name from public.travel_trip_members m where m.trip_id=p_trip_id order by m.created_at;
end $$;

create or replace function public.list_travel_invites(p_trip_id uuid)
returns table(id uuid,role text,expires_at timestamptz,revoked_at timestamptz)
language plpgsql stable security definer set search_path=''
as $$ begin
 if coalesce(travel_private.trip_role(p_trip_id),'')<>'owner' then raise exception '只有建立者可管理' using errcode='42501'; end if;
 return query select i.id,i.role,i.expires_at,i.revoked_at from public.travel_trip_invites i where i.trip_id=p_trip_id order by i.created_at desc;
end $$;

revoke all on function public.list_travel_trips() from public,anon;
revoke all on function public.create_travel_trip(uuid,jsonb) from public,anon;
revoke all on function public.save_travel_trip(uuid,jsonb,bigint) from public,anon;
revoke all on function public.create_travel_invite(uuid,text) from public,anon;
revoke all on function public.accept_travel_invite(text,text) from public,anon;
revoke all on function public.manage_travel_member(uuid,uuid,text) from public,anon;
revoke all on function public.revoke_travel_invite(uuid,uuid) from public,anon;
revoke all on function public.list_travel_members(uuid) from public,anon;
revoke all on function public.list_travel_invites(uuid) from public,anon;
grant execute on function public.list_travel_trips(),public.create_travel_trip(uuid,jsonb),public.save_travel_trip(uuid,jsonb,bigint),public.create_travel_invite(uuid,text),public.accept_travel_invite(text,text),public.manage_travel_member(uuid,uuid,text),public.revoke_travel_invite(uuid,uuid),public.list_travel_members(uuid),public.list_travel_invites(uuid) to authenticated;
commit;
