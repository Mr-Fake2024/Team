-- Run in Supabase SQL Editor as project owner.
create table if not exists public.team_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','technician','viewer')),
  created_at timestamptz not null default now()
);
create table if not exists public.radios (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  model text not null default 'Other',
  location text,
  ip text,
  mac text,
  username text,
  notes text,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
-- Secrets are stored separately so radio metadata can be visible without exposing passwords.
create table if not exists public.radio_secrets (
  radio_id uuid primary key references public.radios(id) on delete cascade,
  password text,
  updated_at timestamptz not null default now()
);
create table if not exists public.radio_access (
  radio_id uuid not null references public.radios(id) on delete cascade,
  user_id uuid not null references public.team_members(user_id) on delete cascade,
  can_view_password boolean not null default false,
  granted_at timestamptz not null default now(),
  primary key (radio_id,user_id)
);

-- Safe migration from the earlier starter schema: move old passwords, then remove that column.
do $$ begin
  if exists (select 1 from information_schema.columns where table_schema='public' and table_name='radios' and column_name='password') then
    insert into public.radio_secrets(radio_id,password)
      select id,password from public.radios where password is not null
      on conflict (radio_id) do update set password=excluded.password;
    alter table public.radios drop column password;
  end if;
end $$;

alter table public.team_members enable row level security;
alter table public.radios enable row level security;
alter table public.radio_secrets enable row level security;
alter table public.radio_access enable row level security;

create or replace function public.is_team_member()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.team_members where user_id=auth.uid()) $$;
create or replace function public.is_team_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.team_members where user_id=auth.uid() and role='admin') $$;
create or replace function public.can_edit_radios()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.team_members where user_id=auth.uid() and role in ('admin','technician')) $$;
create or replace function public.can_view_radio_password(target_radio uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select public.is_team_admin() or exists(select 1 from public.radio_access where radio_id=target_radio and user_id=auth.uid() and can_view_password=true) $$;

-- Admin adds an account after that staff member has registered with Supabase Auth.
create or replace function public.admin_add_team_member(member_email text, member_role text)
returns uuid language plpgsql security definer set search_path=public,auth
as $$ declare new_id uuid; begin
  if not public.is_team_admin() then raise exception 'Not enough privileges'; end if;
  if member_role not in ('admin','technician','viewer') then raise exception 'Invalid role'; end if;
  select id into new_id from auth.users where lower(email)=lower(trim(member_email)) limit 1;
  if new_id is null then raise exception 'No registered account found for that email. Ask the staff member to sign up first.'; end if;
  insert into public.team_members(user_id,role) values(new_id,member_role)
    on conflict(user_id) do update set role=excluded.role;
  return new_id;
end $$;
create or replace function public.admin_list_team_members()
returns table(user_id uuid,email text,role text) language sql stable security definer set search_path=public,auth
as $$ select tm.user_id,au.email::text,tm.role from public.team_members tm join auth.users au on au.id=tm.user_id where public.is_team_admin() order by au.email $$;

revoke all on function public.is_team_member() from public;
revoke all on function public.is_team_admin() from public;
revoke all on function public.can_edit_radios() from public;
revoke all on function public.can_view_radio_password(uuid) from public;
revoke all on function public.admin_add_team_member(text,text) from public;
revoke all on function public.admin_list_team_members() from public;
grant execute on function public.is_team_member() to authenticated;
grant execute on function public.is_team_admin() to authenticated;
grant execute on function public.can_edit_radios() to authenticated;
grant execute on function public.can_view_radio_password(uuid) to authenticated;
grant execute on function public.admin_add_team_member(text,text) to authenticated;
grant execute on function public.admin_list_team_members() to authenticated;

drop policy if exists "team members can view team" on public.team_members;
drop policy if exists "admins manage team" on public.team_members;
drop policy if exists "team can read radios" on public.radios;
drop policy if exists "admins and technicians insert radios" on public.radios;
drop policy if exists "admins and technicians update radios" on public.radios;
drop policy if exists "admins delete radios" on public.radios;
drop policy if exists "authorized users read radio secrets" on public.radio_secrets;
drop policy if exists "editors write radio secrets" on public.radio_secrets;
drop policy if exists "editors insert radio secrets" on public.radio_secrets;
drop policy if exists "editors update radio secrets" on public.radio_secrets;
drop policy if exists "editors delete radio secrets" on public.radio_secrets;
drop policy if exists "admins manage radio access" on public.radio_access;
create policy "team members can view team" on public.team_members for select to authenticated using (public.is_team_member());
create policy "admins manage team" on public.team_members for all to authenticated using (public.is_team_admin()) with check (public.is_team_admin());
create policy "team can read radios" on public.radios for select to authenticated using (public.is_team_member());
create policy "admins and technicians insert radios" on public.radios for insert to authenticated with check (public.can_edit_radios());
create policy "admins and technicians update radios" on public.radios for update to authenticated using (public.can_edit_radios()) with check (public.can_edit_radios());
create policy "admins delete radios" on public.radios for delete to authenticated using (public.is_team_admin());
create policy "authorized users read radio secrets" on public.radio_secrets for select to authenticated using (public.can_view_radio_password(radio_id));
-- Do NOT use FOR ALL here: that would also grant technicians SELECT access to every password.
create policy "editors insert radio secrets" on public.radio_secrets for insert to authenticated with check (public.can_edit_radios());
create policy "editors update radio secrets" on public.radio_secrets for update to authenticated using (public.can_edit_radios()) with check (public.can_edit_radios());
create policy "editors delete radio secrets" on public.radio_secrets for delete to authenticated using (public.can_edit_radios());
create policy "admins manage radio access" on public.radio_access for all to authenticated using (public.is_team_admin()) with check (public.is_team_admin());

-- Bootstrap the first admin after creating the first account. Replace the UUID and run once:
-- insert into public.team_members(user_id, role) values ('USER_UUID', 'admin');
-- Explicit API grants (RLS still decides which rows/columns can be accessed).
grant select, insert, update, delete on public.team_members to authenticated;
grant select, insert, update, delete on public.radios to authenticated;
grant select, insert, update, delete on public.radio_secrets to authenticated;
grant select, insert, update, delete on public.radio_access to authenticated;
