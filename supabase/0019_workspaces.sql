-- ============================================================
-- Yantrika 0019 — SELF-SERVE WORKSPACES + INGEST KEYS (OPT-IN).
--
-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
-- !!  RUN AFTER 0007_rbac.sql — REQUIRES user_roles, yf_rank, !!
-- !!  yf_role and yf_has_role. 0009 (demo sandbox) is NOT      !!
-- !!  required: every reference to it below is guarded, so     !!
-- !!  this file applies cleanly with or without 0009-0017.     !!
-- !!  THIS MIGRATION GIVES THE ANON ROLE A SECOND WRITE PATH   !!
-- !!  (bearer ingest keys). Read the THREAT MODEL before       !!
-- !!  applying. Contract: docs/WORKSPACES.md.                  !!
-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
--
-- A visitor creates an account on yantrika.ai and, with no admin
-- involved, gets a WORKSPACE (their own ``site_id``), an ``admin`` role in
-- it, INGEST KEYS to connect real robots, and a one-click SIMULATED FLEET
-- so the console is never empty. Everything here is additive: a
-- deployment that never applies this file behaves exactly as v0.12 did.
--
-- ------------------------------------------------------------
-- THREAT MODEL — the same five controls as 0009, one more namespace
-- ------------------------------------------------------------
-- 0009 established the rule this file inherits verbatim: identity for a
-- MACHINE is a bearer secret presented in a request header, resolved by
-- exactly one SQL function to exactly one ``site_id``, and every policy
-- is pinned to that one value. The sandbox token (``x-yf-demo-token`` ->
-- ``yf_demo_site()``, namespace ``DEMO-*``) and the ingest key
-- (``x-yf-ingest-key`` -> ``yf_ingest_site()``, namespace ``WS-*``) are
-- the same mechanism. The attacker is a competent, hostile anonymous
-- visitor who holds the publishable key, can create unlimited accounts,
-- can read this file, and sends hand-crafted PostgREST requests.
--
--  1. IDENTITY IS A BEARER SECRET, NOT A ROLE. An ingest key is
--     ``yk_`` + 64 hex (two v4 UUIDs of entropy). Only its SHA-256 hex
--     digest is stored (``ingest_keys.key_hash``); the plaintext is
--     returned exactly once, by the RPC that created it. Guessing one
--     is infeasible; a leaked database dump does not yield working keys.
--
--  2. EVERY POLICY IS PINNED TO ONE SITE. ``yf_ingest_site()`` resolves
--     the header to a single ``WS-*`` site — or NULL for a missing,
--     malformed, revoked, expired or unknown key, and NULL never equals
--     anything — so the anon ``ingest_*`` policies below reduce to
--     ``site_id = <exactly one value>``. Revoking a key makes the very
--     next request answer 401/403 (``yf_ingest_site`` is STABLE: it is
--     evaluated per statement, never cached across requests).
--
--  3. WRITES CANNOT ESCAPE THE SITE. Insert/update policies repeat the
--     predicate in WITH CHECK, so a key holder cannot POST a row stamped
--     with somebody else's ``site_id`` nor PATCH a row from site A to B.
--     Because ``robots.id`` is a global primary key, workspace writers
--     namespace every id with the site (``WS-1a2b3c4d-AMR-01``); the
--     policies would refuse a collision anyway (``on conflict do update``
--     evaluates the UPDATE policy's USING clause against the existing
--     row, as 0017's notes record), so the prefix is a UX measure, not
--     the security boundary.
--
--  4. THE NAMESPACES ARE DISJOINT. ``yf_is_workspace_site()`` requires
--     the ``WS-`` prefix on both sides of every ingest policy, exactly as
--     ``yf_is_demo_site()`` requires ``DEMO-``. A legacy site
--     (``BLR-DC1``) or a demo site can never be addressed by an ingest
--     key, and a workspace can never be addressed by a demo token.
--
--  5. THE PRIVILEGE SURFACE IS ENUMERATED, NOT INHERITED. anon gets
--     SELECT/INSERT/UPDATE on exactly the seven site-scoped fleet
--     tables, with the same column-level UPDATE grants 0009 chose for
--     ``alerts`` (ack) and ``commands`` (status, decided_by, decided_at,
--     note, executed_at). anon gets NO DELETE anywhere, NO access to
--     ``fleet_meta`` (no site_id — nothing to scope it by, so workspace
--     writers never write it), and NO access to any of the four tables
--     this file creates: they are reachable only through the SECURITY
--     DEFINER RPCs, every one of which checks 0007's ``yf_has_role``.
--
-- RESIDUAL RISKS, stated plainly:
--   * Row-count abuse inside one's own workspace. Bounded by the plan
--     (not enforced here — ``workspaces.plan`` is a label this migration
--     records and the console reads) and by ``workspace_purge_fleet``,
--     which lets an admin wipe their own fleet tables in one call.
--   * A key is a bearer credential: whoever holds it holds that one
--     workspace's fleet tables. That is the intended, and only,
--     consequence of leaking it; ``workspace_revoke_ingest_key`` is the
--     remedy and takes effect on the next request.
--   * Account creation is open. The trigger provisions one workspace per
--     ``auth.users`` row; abuse of sign-up itself is Supabase Auth's
--     rate limiting to handle, not this file's.
--
-- Run after 0018_app_config.sql. Idempotent. ROLLBACK block at the bottom.
-- ============================================================


-- ------------------------------------------------------------
-- 1) Tables
-- ------------------------------------------------------------

create table if not exists public.workspaces (
  site_id     text primary key,                       -- 'WS-<8 lowercase hex>'
  name        text not null,
  owner_id    uuid references auth.users (id) on delete set null,
  plan        text not null default 'free'
              check (plan in ('free', 'team', 'enterprise')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.ingest_keys (
  id          uuid primary key default gen_random_uuid(),
  site_id     text not null references public.workspaces (site_id) on delete cascade,
  key_hash    text not null unique,                   -- sha256 hex of the plaintext
  prefix      text not null,                          -- first 12 chars, for display only
  label       text not null default 'default',
  kind        text not null default 'integration'
              check (kind in ('integration', 'sim')),
  created_by  uuid,                                   -- auth.users id, no FK: survives account deletion
  created_at  timestamptz not null default now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);

create index if not exists ingest_keys_site_live
  on public.ingest_keys (site_id) where revoked_at is null;

create table if not exists public.workspace_invites (
  id          uuid primary key default gen_random_uuid(),
  site_id     text not null references public.workspaces (site_id) on delete cascade,
  email       text not null,                          -- always lowercased by the RPC
  role        text not null check (role in ('operator', 'engineer', 'manager', 'admin')),
  invited_by  uuid,
  created_at  timestamptz not null default now(),
  accepted_at timestamptz,
  unique (site_id, email)
);

create index if not exists workspace_invites_email
  on public.workspace_invites (email) where accepted_at is null;

create table if not exists public.workspace_sims (
  site_id     text primary key references public.workspaces (site_id) on delete cascade,
  key_id      uuid references public.ingest_keys (id) on delete set null,
  started_by  uuid,
  started_at  timestamptz not null default now(),
  expires_at  timestamptz not null,
  robots      int not null default 8,
  stopped_at  timestamptz
);

alter table public.workspaces        enable row level security;
alter table public.ingest_keys       enable row level security;
alter table public.workspace_invites enable row level security;
alter table public.workspace_sims    enable row level security;

-- anon has no access to any of the four tables. authenticated may only
-- SELECT workspaces it holds a role in; everything else goes through the
-- SECURITY DEFINER RPCs below. ingest_keys in particular must never be
-- listable: a hash is not a key, but a prefix plus a label is a map of
-- what to phish for.
revoke all on public.workspaces        from anon, authenticated;
revoke all on public.ingest_keys       from anon, authenticated;
revoke all on public.workspace_invites from anon, authenticated;
revoke all on public.workspace_sims    from anon, authenticated;
grant select on public.workspaces to authenticated;

drop policy if exists workspaces_member_read on public.workspaces;
create policy workspaces_member_read on public.workspaces
  for select to authenticated
  using (public.yf_has_role('operator', site_id));


-- ------------------------------------------------------------
-- 2) Helpers
-- ------------------------------------------------------------

-- Namespace guard: workspace site ids live in a disjoint prefix, and the
-- minted shape is fixed so a hand-typed ``WS-anything`` cannot be a site.
create or replace function public.yf_is_workspace_site(p_site text)
returns boolean
language sql immutable
set search_path = ''
as $$
  select p_site is not null and p_site ~ '^WS-[0-9a-f]{8}$'
$$;

-- The ingest key presented on THIS request, from the ``x-yf-ingest-key``
-- header. NULL outside a PostgREST request, or when the header is absent,
-- blank or malformed. Never raises — a broken header context must not
-- turn into a 500 on every fleet read.
create or replace function public.yf_ingest_key()
returns text
language plpgsql stable
set search_path = ''
as $$
declare
  v_headers text;
  v_key     text;
begin
  begin
    v_headers := current_setting('request.headers', true);
  exception when others then
    return null;
  end;
  if v_headers is null or length(v_headers) = 0 then
    return null;
  end if;
  begin
    v_key := (v_headers::json ->> 'x-yf-ingest-key');
  exception when others then
    return null;
  end;
  v_key := nullif(btrim(coalesce(v_key, '')), '');
  -- Shape guard: 'yk_' + 64 lowercase hex, nothing else. Keeps junk out
  -- of the hash + index probe below and makes the key format a contract.
  if v_key is null or v_key !~ '^yk_[0-9a-f]{64}$' then
    return null;
  end if;
  return v_key;
end
$$;

-- SHA-256 hex of a plaintext key. Built-in ``sha256(bytea)`` (PostgreSQL
-- 11+) — deliberately NOT pgcrypto, so the file needs no extension.
create or replace function public.yf_ingest_key_hash(p_key text)
returns text
language sql immutable
set search_path = ''
as $$
  select encode(sha256(convert_to(p_key, 'UTF8')), 'hex')
$$;

-- The one site_id this request's ingest key may touch, or NULL.
-- SECURITY DEFINER: ingest_keys has no grants for anon at all, but the
-- policies below (which run as anon) must be able to resolve the key.
-- Leaks nothing — you only ever learn the site behind a key you hold.
create or replace function public.yf_ingest_site()
returns text
language sql stable security definer
set search_path = ''
as $$
  select k.site_id
    from public.ingest_keys k
    join public.workspaces w on w.site_id = k.site_id
   where k.key_hash = public.yf_ingest_key_hash(public.yf_ingest_key())
     and k.revoked_at is null
     and (k.expires_at is null or k.expires_at > now())
     and public.yf_is_workspace_site(k.site_id)
$$;

-- The site-read gate 0011-0016 reuse. Re-issued here so an ingest key
-- holder passes for its own WS- site, keeping 0009's two branches:
-- operator+ at this site (admins global), or this request's own live demo
-- sandbox. The demo branch is resolved DYNAMICALLY so this file still
-- applies to a project that hardened with 0007 but never enabled 0009
-- (``yf_demo_site()`` does not exist there, and a static reference would
-- fail the whole migrate run — the same trap 0017 documents).
create or replace function public.yf_can_read_site(p_site text)
returns boolean
language plpgsql stable security definer
set search_path = ''
as $$
declare
  v_demo text;
begin
  if p_site is null then
    return false;
  end if;
  if public.yf_is_workspace_site(p_site) and p_site = public.yf_ingest_site() then
    return true;
  end if;
  if p_site like 'DEMO-%' and to_regprocedure('public.yf_demo_site()') is not null then
    execute 'select public.yf_demo_site()' into v_demo;
    if v_demo is not null and v_demo = p_site then
      return true;
    end if;
  end if;
  return public.yf_has_role('operator', p_site);
end
$$;

revoke execute on function public.yf_ingest_site()             from public;
revoke execute on function public.yf_ingest_key_hash(text)     from public, anon;
revoke execute on function public.yf_can_read_site(text)       from public;
grant  execute on function public.yf_is_workspace_site(text)   to anon, authenticated, service_role;
grant  execute on function public.yf_ingest_key()              to anon, authenticated, service_role;
grant  execute on function public.yf_ingest_key_hash(text)     to authenticated, service_role;
grant  execute on function public.yf_ingest_site()             to anon, authenticated, service_role;
grant  execute on function public.yf_can_read_site(text)       to anon, authenticated, service_role;


-- ------------------------------------------------------------
-- 2b) yf_has_role: a WORKSPACE admin is admin of that workspace only
-- ------------------------------------------------------------
-- 0007 defines "admin" as GLOBAL: holding 'admin' at any one site passes
-- yf_has_role for every site, because on a self-hosted deployment the
-- admins are the operator's own staff. Self-serve breaks that premise —
-- the trigger above hands every stranger who signs up an 'admin' row —
-- so, unchanged, 0007's clause would make each new account an admin of
-- the legacy fleet and of every other workspace. This replacement keeps
-- 0007's behaviour to the letter for roles at legacy sites (an admin at
-- BLR-DC1 still sees everything, including every workspace, which is
-- what a platform operator needs) and confines an admin role held AT a
-- WS-* site to that one workspace. Same signature, same grants, so
-- nothing in 0007-0018 notices. This is the one deliberate deviation
-- from docs/WORKSPACES.md's "role checks use 0007's yf_has_role" and is
-- recorded there.
create or replace function public.yf_has_role(p_min_role text, p_site text default 'BLR-DC1')
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select coalesce(
           (select public.yf_rank(ur.role) >= public.yf_rank(p_min_role)
              from public.user_roles ur
             where ur.user_id = auth.uid()
               and ur.site_id = p_site),
           false)
      or exists (select 1
                   from public.user_roles ur
                  where ur.user_id = auth.uid()
                    and ur.role = 'admin'
                    and not public.yf_is_workspace_site(ur.site_id))
$$;

revoke execute on function public.yf_has_role(text, text) from public, anon;
grant  execute on function public.yf_has_role(text, text) to authenticated, service_role;


-- ------------------------------------------------------------
-- 3) THE ANON INGEST POLICIES — controls 2/3/4 of the threat model.
-- ------------------------------------------------------------

do $$
declare t text;
begin
  foreach t in array array[
    'robots', 'alerts', 'incidents', 'missions',
    'robot_telemetry', 'maintenance_findings', 'commands'
  ] loop
    execute format('alter table public.%I enable row level security', t);

    execute format('drop policy if exists ingest_read on public.%I', t);
    execute format(
      'create policy ingest_read on public.%I
         for select to anon
         using (public.yf_is_workspace_site(site_id)
                and site_id = public.yf_ingest_site())', t);

    execute format('drop policy if exists ingest_insert on public.%I', t);
    execute format(
      'create policy ingest_insert on public.%I
         for insert to anon
         with check (public.yf_is_workspace_site(site_id)
                     and site_id = public.yf_ingest_site())', t);

    execute format('drop policy if exists ingest_update on public.%I', t);
    execute format(
      'create policy ingest_update on public.%I
         for update to anon
         using (public.yf_is_workspace_site(site_id)
                and site_id = public.yf_ingest_site())
         with check (public.yf_is_workspace_site(site_id)
                     and site_id = public.yf_ingest_site())', t);
  end loop;
end $$;

-- Control 5: the enumerated privilege surface, re-issued in full so it is
-- correct whether or not 0009 ever ran on this project. Policies are OR-ed
-- by PostgreSQL, so on a project with 0009 the demo policies and these
-- coexist and each one is still pinned to its own header's single site.
grant select, insert, update on
  public.robots, public.incidents, public.missions,
  public.robot_telemetry, public.maintenance_findings to anon;

-- alerts / commands keep 0007's operator posture at the column level: RLS
-- is row-level, so these grants are what stop a key holder from rewriting
-- an alert's text or back-dating a command decision inside its own site.
revoke update on public.alerts   from anon;
revoke update on public.commands from anon;
grant  select, insert on public.alerts   to anon;
grant  select, insert on public.commands to anon;
grant  update (ack) on public.alerts to anon;
grant  update (status, decided_by, decided_at, note, executed_at)
  on public.commands to anon;

-- No DELETE, for anyone, anywhere. There is no ``for delete`` policy above
-- (RLS already blocks it); the table-wide privilege Supabase hands anon by
-- default goes away too, so two independent controls stand between a key
-- and a deleted row. Only ``workspace_purge_fleet`` (SECURITY DEFINER,
-- admin-gated, own site only) deletes.
do $$
declare t text;
begin
  foreach t in array array[
    'robots', 'alerts', 'incidents', 'missions',
    'robot_telemetry', 'maintenance_findings', 'commands'
  ] loop
    execute format('revoke delete, truncate, references, trigger on public.%I from anon', t);
  end loop;
end $$;

-- fleet_meta has no site_id (0005): nothing to scope a key by, so it stays
-- entirely off-limits and workspace writers never write it. Stated
-- explicitly so a future reader does not "fix" the omission.
revoke all on public.fleet_meta from anon;


-- ------------------------------------------------------------
-- 4) Provisioning: the auth.users trigger and its shared helper
-- ------------------------------------------------------------

-- Create a workspace for a user who has none. Shared by the sign-up
-- trigger and ``workspace_bootstrap`` (accounts that predate this file).
-- Returns the new site_id. Idempotent per user: a second call for a user
-- who already holds ANY role returns that user's existing site instead of
-- minting another workspace — one person, one default workspace.
create or replace function public._yf_provision_workspace(p_user_id uuid, p_email text)
returns text
language plpgsql security definer
set search_path = ''
as $$
declare
  v_site  text;
  v_name  text;
  v_local text;
  v_inv   record;
begin
  if p_user_id is null then
    return null;
  end if;
  select ur.site_id into v_site
    from public.user_roles ur
   where ur.user_id = p_user_id
   order by ur.granted_at asc
   limit 1;
  if v_site is not null then
    return v_site;
  end if;

  v_local := nullif(split_part(coalesce(p_email, ''), '@', 1), '');
  v_name  := coalesce(v_local, 'My') || '''s workspace';

  -- 8 lowercase hex: 4 billion ids, and the shape yf_is_workspace_site
  -- enforces. Loop on the (astronomically unlikely) collision rather than
  -- failing a sign-up over it.
  loop
    v_site := 'WS-' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8);
    exit when not exists (select 1 from public.workspaces w where w.site_id = v_site);
  end loop;

  insert into public.workspaces (site_id, name, owner_id)
  values (v_site, v_name, p_user_id);

  insert into public.user_roles (user_id, site_id, role)
  values (p_user_id, v_site, 'admin')
  on conflict (user_id, site_id) do update set role = 'admin';

  -- Consume every pending invite for this email: the invited roles are
  -- granted at the inviting workspaces, and the invite rows are stamped
  -- rather than deleted so an admin can see that it was accepted.
  for v_inv in
    select i.id, i.site_id, i.role
      from public.workspace_invites i
     where i.accepted_at is null
       and i.email = lower(btrim(coalesce(p_email, '')))
       and i.email <> ''
  loop
    insert into public.user_roles (user_id, site_id, role)
    values (p_user_id, v_inv.site_id, v_inv.role)
    on conflict (user_id, site_id) do update set role = excluded.role;
    update public.workspace_invites set accepted_at = now() where id = v_inv.id;
  end loop;

  return v_site;
end
$$;

-- AFTER INSERT on auth.users. Never lets a provisioning error fail the
-- sign-up itself: Supabase Auth would report the error to the visitor as
-- a failed registration, which is far worse than a workspace that
-- ``workspace_bootstrap`` can create on first sign-in instead.
create or replace function public.yf_handle_new_user()
returns trigger
language plpgsql security definer
set search_path = ''
as $$
begin
  begin
    perform public._yf_provision_workspace(new.id, new.email);
  exception when others then
    raise warning 'yf_handle_new_user: could not provision a workspace for %: %',
      new.id, sqlerrm;
  end;
  return new;
end
$$;

drop trigger if exists yf_on_auth_user_created on auth.users;
create trigger yf_on_auth_user_created
  after insert on auth.users
  for each row execute function public.yf_handle_new_user();

revoke execute on function public._yf_provision_workspace(uuid, text) from public, anon, authenticated;
revoke execute on function public.yf_handle_new_user()               from public, anon, authenticated;


-- ------------------------------------------------------------
-- 5) RPCs — every one returns jsonb {ok, ...} and never raises for an
--    expected refusal: a console wants ``{ok:false, reason:'forbidden'}``
--    it can render, not a 400 with prose to parse. Role checks use
--    0007's yf_has_role(min_role, site); "admin" means admin at THAT
--    workspace (or a global admin, which 0007 defines as admin anywhere).
-- ------------------------------------------------------------

-- The caller's workspace: the site where they are owner, else their
-- highest role, else their oldest grant. NULL for a caller with no role
-- anywhere. Shared by every RPC that takes no site argument.
create or replace function public._yf_my_site()
returns text
language sql stable security definer
set search_path = ''
as $$
  select ur.site_id
    from public.user_roles ur
    left join public.workspaces w on w.site_id = ur.site_id
   where ur.user_id = auth.uid()
   order by (w.owner_id = auth.uid()) desc nulls last,
            public.yf_rank(ur.role) desc nulls last,
            ur.granted_at asc
   limit 1
$$;

-- The refusal envelopes, in one place so every RPC spells them the same.
create or replace function public._yf_ws_refuse(p_reason text, p_error text)
returns jsonb
language sql immutable
set search_path = ''
as $$
  select jsonb_build_object('ok', false, 'reason', p_reason, 'error', p_error)
$$;

-- Admin gate shared by the mutating RPCs: NULL when the caller is an admin
-- at their workspace (and v_site has been resolved), else the refusal.
create or replace function public._yf_ws_admin_gate(out o_site text, out o_refusal jsonb)
language plpgsql stable security definer
set search_path = ''
as $$
begin
  o_site := null;
  o_refusal := null;
  if auth.uid() is null then
    o_refusal := public._yf_ws_refuse('unauthenticated', 'Sign in first.');
    return;
  end if;
  o_site := public._yf_my_site();
  if o_site is null then
    o_refusal := public._yf_ws_refuse('no_workspace',
      'You do not belong to any workspace yet — call workspace_bootstrap().');
    return;
  end if;
  if not public.yf_has_role('admin', o_site) then
    o_refusal := public._yf_ws_refuse('forbidden',
      'This action requires the admin role at workspace ' || o_site || '.');
    return;
  end if;
end
$$;

-- -- my_workspace() ------------------------------------------------------
create or replace function public.my_workspace()
returns jsonb
language plpgsql stable security definer
set search_path = ''
as $$
declare
  v_site    text;
  v_ws      public.workspaces%rowtype;
  v_role    text;
  v_admin   boolean;
  v_keys    jsonb := '[]'::jsonb;
  v_sim     jsonb;
  v_members jsonb := '[]'::jsonb;
  v_invites jsonb := '[]'::jsonb;
  v_sims    public.workspace_sims%rowtype;
begin
  if auth.uid() is null then
    return public._yf_ws_refuse('unauthenticated', 'Sign in first.');
  end if;
  v_site := public._yf_my_site();
  if v_site is null then
    return jsonb_build_object('ok', true, 'site_id', null);
  end if;

  select ur.role into v_role
    from public.user_roles ur
   where ur.user_id = auth.uid() and ur.site_id = v_site;
  v_admin := public.yf_has_role('admin', v_site);

  select * into v_ws from public.workspaces w where w.site_id = v_site;
  select * into v_sims from public.workspace_sims s where s.site_id = v_site;

  v_sim := jsonb_build_object(
    'running',    (v_sims.site_id is not null and v_sims.stopped_at is null
                   and v_sims.expires_at > now()),
    'expires_at', v_sims.expires_at,
    'robots',     v_sims.robots,
    'started_at', v_sims.started_at);

  if v_ws.site_id is not null then
    -- Hashes are never returned; the prefix is what the console shows.
    select coalesce(jsonb_agg(jsonb_build_object(
             'id', k.id, 'prefix', k.prefix, 'label', k.label, 'kind', k.kind,
             'created_at', k.created_at, 'expires_at', k.expires_at)
             order by k.created_at desc), '[]'::jsonb)
      into v_keys
      from public.ingest_keys k
     where k.site_id = v_site
       and k.revoked_at is null
       and (k.expires_at is null or k.expires_at > now());
  end if;

  if v_admin then
    -- Member emails come from auth.users, readable here only because the
    -- function is SECURITY DEFINER and only for admins of this workspace.
    select coalesce(jsonb_agg(jsonb_build_object(
             'user_id', ur.user_id, 'email', u.email, 'role', ur.role,
             'granted_at', ur.granted_at)
             order by ur.granted_at asc), '[]'::jsonb)
      into v_members
      from public.user_roles ur
      left join auth.users u on u.id = ur.user_id
     where ur.site_id = v_site;
    select coalesce(jsonb_agg(jsonb_build_object(
             'id', i.id, 'email', i.email, 'role', i.role,
             'created_at', i.created_at)
             order by i.created_at desc), '[]'::jsonb)
      into v_invites
      from public.workspace_invites i
     where i.site_id = v_site and i.accepted_at is null;
  end if;

  return jsonb_build_object(
    'ok',         true,
    'site_id',    v_site,
    'name',       coalesce(v_ws.name, v_site),
    'plan',       coalesce(v_ws.plan, 'self-hosted'),
    'role',       v_role,
    'owner',      (v_ws.owner_id is not null and v_ws.owner_id = auth.uid()),
    'owner_id',   v_ws.owner_id,
    'created_at', v_ws.created_at,
    'keys',       v_keys,
    'sim',        v_sim,
    'members',    v_members,
    'invites',    v_invites);
end
$$;

-- -- workspace_bootstrap() -----------------------------------------------
-- For accounts created before 0019 (the trigger never ran for them), and
-- as the console's fallback when my_workspace() reports site_id null.
-- Provisions ONLY when the caller holds no user_roles row at all.
create or replace function public.workspace_bootstrap()
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    return public._yf_ws_refuse('unauthenticated', 'Sign in first.');
  end if;
  if not exists (select 1 from public.user_roles ur where ur.user_id = auth.uid()) then
    perform public._yf_provision_workspace(auth.uid(), auth.email());
  end if;
  return public.my_workspace();
end
$$;

-- -- workspace_rename(p_name) ----------------------------------------------
create or replace function public.workspace_rename(p_name text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate record;
  v_name text;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  v_name := btrim(coalesce(p_name, ''));
  if length(v_name) < 1 or length(v_name) > 60 then
    return public._yf_ws_refuse('invalid_name',
      'A workspace name is 1 to 60 characters.');
  end if;
  update public.workspaces
     set name = v_name, updated_at = now()
   where site_id = v_gate.o_site;
  if not found then
    return public._yf_ws_refuse('not_workspace',
      'Site ' || v_gate.o_site || ' is not a self-serve workspace.');
  end if;
  return jsonb_build_object('ok', true, 'name', v_name);
end
$$;

-- -- workspace_create_ingest_key(p_label) ------------------------------------
create or replace function public.workspace_create_ingest_key(p_label text default 'default')
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate  record;
  v_key   text;
  v_id    uuid;
  v_label text;
  v_live  int;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  if not exists (select 1 from public.workspaces w where w.site_id = v_gate.o_site) then
    return public._yf_ws_refuse('not_workspace',
      'Site ' || v_gate.o_site || ' is not a self-serve workspace.');
  end if;
  select count(*) into v_live
    from public.ingest_keys k
   where k.site_id = v_gate.o_site and k.kind = 'integration'
     and k.revoked_at is null
     and (k.expires_at is null or k.expires_at > now());
  if v_live >= 10 then
    return public._yf_ws_refuse('too_many_keys',
      'This workspace already has 10 active integration keys — revoke one first.');
  end if;
  v_label := left(btrim(coalesce(p_label, '')), 60);
  if v_label = '' then
    v_label := 'default';
  end if;
  -- 2 x v4 UUID of entropy, hex only (matches yf_ingest_key's shape guard).
  v_key := 'yk_' || replace(gen_random_uuid()::text, '-', '')
                 || replace(gen_random_uuid()::text, '-', '');
  insert into public.ingest_keys (site_id, key_hash, prefix, label, kind, created_by)
  values (v_gate.o_site, public.yf_ingest_key_hash(v_key), left(v_key, 12),
          v_label, 'integration', auth.uid())
  returning id into v_id;
  -- The plaintext appears here and nowhere else — it is never stored.
  return jsonb_build_object('ok', true, 'id', v_id, 'key', v_key,
                            'prefix', left(v_key, 12), 'label', v_label);
end
$$;

-- -- workspace_revoke_ingest_key(p_id) ---------------------------------------
-- Idempotent: revoking twice, or revoking an id that is not this
-- workspace's, answers {ok:true} without touching anything — an admin
-- learns nothing about other workspaces' key ids.
create or replace function public.workspace_revoke_ingest_key(p_id uuid)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate record;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  update public.ingest_keys
     set revoked_at = coalesce(revoked_at, now())
   where id = p_id and site_id = v_gate.o_site;
  return jsonb_build_object('ok', true);
end
$$;

-- -- workspace_invite(p_email, p_role) ---------------------------------------
create or replace function public.workspace_invite(p_email text, p_role text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate  record;
  v_email text;
  v_uid   uuid;
  v_owner uuid;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  if p_role is null or p_role not in ('operator', 'engineer', 'manager', 'admin') then
    return public._yf_ws_refuse('invalid_role',
      'Role must be one of operator, engineer, manager, admin.');
  end if;
  v_email := lower(btrim(coalesce(p_email, '')));
  if v_email = '' or v_email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then
    return public._yf_ws_refuse('invalid_email', 'That is not an email address.');
  end if;
  select w.owner_id into v_owner from public.workspaces w where w.site_id = v_gate.o_site;

  select u.id into v_uid from auth.users u where lower(u.email) = v_email limit 1;
  if v_uid is not null then
    if v_owner is not null and v_uid = v_owner and p_role <> 'admin' then
      return public._yf_ws_refuse('owner',
        'The workspace owner is always an admin and cannot be demoted.');
    end if;
    insert into public.user_roles (user_id, site_id, role)
    values (v_uid, v_gate.o_site, p_role)
    on conflict (user_id, site_id) do update set role = excluded.role;
    return jsonb_build_object('ok', true, 'status', 'added',
                              'email', v_email, 'role', p_role);
  end if;

  insert into public.workspace_invites (site_id, email, role, invited_by)
  values (v_gate.o_site, v_email, p_role, auth.uid())
  on conflict (site_id, email) do update
    set role = excluded.role, invited_by = excluded.invited_by,
        created_at = now(), accepted_at = null;
  return jsonb_build_object('ok', true, 'status', 'invited',
                            'email', v_email, 'role', p_role);
end
$$;

-- -- workspace_set_member_role(p_user_id, p_role) ------------------------------
create or replace function public.workspace_set_member_role(p_user_id uuid, p_role text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate  record;
  v_owner uuid;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  if p_role is null or p_role not in ('operator', 'engineer', 'manager', 'admin') then
    return public._yf_ws_refuse('invalid_role',
      'Role must be one of operator, engineer, manager, admin.');
  end if;
  select w.owner_id into v_owner from public.workspaces w where w.site_id = v_gate.o_site;
  if v_owner is not null and p_user_id = v_owner then
    return public._yf_ws_refuse('owner',
      'The workspace owner is always an admin and cannot be changed.');
  end if;
  update public.user_roles
     set role = p_role
   where user_id = p_user_id and site_id = v_gate.o_site;
  if not found then
    return public._yf_ws_refuse('not_member',
      'That user is not a member of this workspace.');
  end if;
  return jsonb_build_object('ok', true);
end
$$;

-- -- workspace_remove_member(p_user_id) --------------------------------------
create or replace function public.workspace_remove_member(p_user_id uuid)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate  record;
  v_owner uuid;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  select w.owner_id into v_owner from public.workspaces w where w.site_id = v_gate.o_site;
  if v_owner is not null and p_user_id = v_owner then
    return public._yf_ws_refuse('owner',
      'The workspace owner cannot be removed from their own workspace.');
  end if;
  delete from public.user_roles
   where user_id = p_user_id and site_id = v_gate.o_site;
  return jsonb_build_object('ok', true);
end
$$;

-- -- workspace_cancel_invite(p_id) -----------------------------------------
create or replace function public.workspace_cancel_invite(p_id uuid)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate record;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  delete from public.workspace_invites
   where id = p_id and site_id = v_gate.o_site and accepted_at is null;
  return jsonb_build_object('ok', true);
end
$$;

-- -- workspace_sim_start(p_minutes, p_robots) --------------------------------
-- Mints a fresh ``sim``-kind key (revoking any previous one, so at most
-- one simulator holds a live key per workspace) and records the run. The
-- key is returned to the caller — normally the door, which hands it to
-- ``yantraops sandbox-drive --auth ingest`` through the environment.
create or replace function public.workspace_sim_start(p_minutes int default 240,
                                                      p_robots  int default 8)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate    record;
  v_minutes int;
  v_robots  int;
  v_key     text;
  v_id      uuid;
  v_expires timestamptz;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  if not public.yf_is_workspace_site(v_gate.o_site)
     or not exists (select 1 from public.workspaces w where w.site_id = v_gate.o_site) then
    return public._yf_ws_refuse('not_workspace',
      'Simulated fleets run only in self-serve workspaces (WS-*), not in '
      || v_gate.o_site || '.');
  end if;
  v_minutes := least(greatest(coalesce(p_minutes, 240), 5), 1440);
  v_robots  := least(greatest(coalesce(p_robots, 8), 2), 20);
  v_expires := now() + make_interval(mins => v_minutes);

  update public.ingest_keys
     set revoked_at = now()
   where site_id = v_gate.o_site and kind = 'sim' and revoked_at is null;

  v_key := 'yk_' || replace(gen_random_uuid()::text, '-', '')
                 || replace(gen_random_uuid()::text, '-', '');
  insert into public.ingest_keys (site_id, key_hash, prefix, label, kind,
                                  created_by, expires_at)
  values (v_gate.o_site, public.yf_ingest_key_hash(v_key), left(v_key, 12),
          'simulated fleet', 'sim', auth.uid(), v_expires)
  returning id into v_id;

  insert into public.workspace_sims (site_id, key_id, started_by, started_at,
                                     expires_at, robots, stopped_at)
  values (v_gate.o_site, v_id, auth.uid(), now(), v_expires, v_robots, null)
  on conflict (site_id) do update
    set key_id = excluded.key_id, started_by = excluded.started_by,
        started_at = now(), expires_at = excluded.expires_at,
        robots = excluded.robots, stopped_at = null;

  return jsonb_build_object('ok', true, 'site_id', v_gate.o_site, 'key', v_key,
                            'expires_at', v_expires, 'robots', v_robots);
end
$$;

-- -- workspace_sim_stop() -----------------------------------------------------
-- Returns the site_id too (additive to the documented {ok}) so the door
-- can SIGTERM the right local driver without a second round trip.
create or replace function public.workspace_sim_stop()
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate record;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  update public.ingest_keys
     set revoked_at = now()
   where site_id = v_gate.o_site and kind = 'sim' and revoked_at is null;
  update public.workspace_sims
     set stopped_at = coalesce(stopped_at, now())
   where site_id = v_gate.o_site;
  return jsonb_build_object('ok', true, 'site_id', v_gate.o_site);
end
$$;

-- -- workspace_sim_status() ---------------------------------------------------
create or replace function public.workspace_sim_status()
returns jsonb
language plpgsql stable security definer
set search_path = ''
as $$
declare
  v_site text;
  v_row  public.workspace_sims%rowtype;
begin
  if auth.uid() is null then
    return public._yf_ws_refuse('unauthenticated', 'Sign in first.');
  end if;
  v_site := public._yf_my_site();
  if v_site is null then
    return public._yf_ws_refuse('no_workspace',
      'You do not belong to any workspace yet — call workspace_bootstrap().');
  end if;
  if not public.yf_has_role('operator', v_site) then
    return public._yf_ws_refuse('forbidden',
      'This action requires at least the operator role at ' || v_site || '.');
  end if;
  select * into v_row from public.workspace_sims s where s.site_id = v_site;
  return jsonb_build_object(
    'ok',         true,
    'site_id',    v_site,
    'running',    (v_row.site_id is not null and v_row.stopped_at is null
                   and v_row.expires_at > now()),
    'expires_at', v_row.expires_at,
    'robots',     v_row.robots,
    'started_at', v_row.started_at);
end
$$;

-- -- workspace_purge_fleet() --------------------------------------------------
-- The ONLY delete path this migration adds. Scoped to the caller's own
-- workspace, and refuses outright for a site that has no workspaces row
-- (a legacy fleet or a demo sandbox): a caller bug must never become
-- data loss on a real fleet.
create or replace function public.workspace_purge_fleet()
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_gate   record;
  t        text;
  v_n      bigint;
  v_counts jsonb := '{}'::jsonb;
begin
  select * into v_gate from public._yf_ws_admin_gate();
  if v_gate.o_refusal is not null then
    return v_gate.o_refusal;
  end if;
  if not public.yf_is_workspace_site(v_gate.o_site)
     or not exists (select 1 from public.workspaces w where w.site_id = v_gate.o_site) then
    return public._yf_ws_refuse('not_workspace',
      'Only a self-serve workspace (WS-*) can be purged; ' || v_gate.o_site
      || ' is not one.');
  end if;
  foreach t in array array[
    'robot_telemetry', 'maintenance_findings', 'commands',
    'alerts', 'incidents', 'missions', 'robots'
  ] loop
    execute format('delete from public.%I where site_id = $1', t) using v_gate.o_site;
    get diagnostics v_n = row_count;
    v_counts := v_counts || jsonb_build_object(t, v_n);
  end loop;
  return jsonb_build_object('ok', true, 'site_id', v_gate.o_site, 'deleted', v_counts);
end
$$;

-- Grants: the internal helpers reach nobody; the RPCs reach signed-in
-- users and the service role, never anon.
revoke execute on function public._yf_my_site()                              from public, anon, authenticated;
revoke execute on function public._yf_ws_refuse(text, text)                  from public, anon, authenticated;
revoke execute on function public._yf_ws_admin_gate()                        from public, anon, authenticated;
revoke execute on function public.my_workspace()                             from public, anon;
revoke execute on function public.workspace_bootstrap()                      from public, anon;
revoke execute on function public.workspace_rename(text)                     from public, anon;
revoke execute on function public.workspace_create_ingest_key(text)          from public, anon;
revoke execute on function public.workspace_revoke_ingest_key(uuid)          from public, anon;
revoke execute on function public.workspace_invite(text, text)               from public, anon;
revoke execute on function public.workspace_set_member_role(uuid, text)      from public, anon;
revoke execute on function public.workspace_remove_member(uuid)              from public, anon;
revoke execute on function public.workspace_cancel_invite(uuid)              from public, anon;
revoke execute on function public.workspace_sim_start(int, int)              from public, anon;
revoke execute on function public.workspace_sim_stop()                       from public, anon;
revoke execute on function public.workspace_sim_status()                     from public, anon;
revoke execute on function public.workspace_purge_fleet()                    from public, anon;

grant execute on function public.my_workspace()                         to authenticated, service_role;
grant execute on function public.workspace_bootstrap()                  to authenticated, service_role;
grant execute on function public.workspace_rename(text)                 to authenticated, service_role;
grant execute on function public.workspace_create_ingest_key(text)      to authenticated, service_role;
grant execute on function public.workspace_revoke_ingest_key(uuid)      to authenticated, service_role;
grant execute on function public.workspace_invite(text, text)           to authenticated, service_role;
grant execute on function public.workspace_set_member_role(uuid, text)  to authenticated, service_role;
grant execute on function public.workspace_remove_member(uuid)          to authenticated, service_role;
grant execute on function public.workspace_cancel_invite(uuid)          to authenticated, service_role;
grant execute on function public.workspace_sim_start(int, int)          to authenticated, service_role;
grant execute on function public.workspace_sim_stop()                   to authenticated, service_role;
grant execute on function public.workspace_sim_status()                 to authenticated, service_role;
grant execute on function public.workspace_purge_fleet()                to authenticated, service_role;

select 'v0.13 WORKSPACES: workspaces/ingest_keys/workspace_invites/workspace_sims + 13 jsonb RPCs; auth.users trigger provisions WS-<hex> + admin role; anon ingest_* policies pinned to one WS-* site by x-yf-ingest-key (sha256 at rest); yf_can_read_site() extended for ingest keys' as result;


-- ============================================================
-- ROLLBACK (uncomment to run) — remove workspaces entirely.
-- Drops the trigger first (so sign-ups stop provisioning), then the anon
-- ingest policies, the RPCs, the helpers and the tables. The user_roles
-- rows the trigger granted are left in place (they are 0007's data, and
-- harmless); fleet rows written under WS-* sites are NOT deleted — run
-- workspace_purge_fleet() per workspace beforehand if you want them gone.
-- yf_can_read_site() is restored to 0009's definition when 0009 is
-- present; on a project without 0009 it is simply dropped.
-- ------------------------------------------------------------
-- drop trigger if exists yf_on_auth_user_created on auth.users;
-- drop function if exists public.yf_handle_new_user();
--
-- do $$
-- declare t text;
-- begin
--   foreach t in array array[
--     'robots', 'alerts', 'incidents', 'missions',
--     'robot_telemetry', 'maintenance_findings', 'commands'
--   ] loop
--     execute format('drop policy if exists ingest_read   on public.%I', t);
--     execute format('drop policy if exists ingest_insert on public.%I', t);
--     execute format('drop policy if exists ingest_update on public.%I', t);
--   end loop;
-- end $$;
--
-- drop function if exists public.workspace_purge_fleet();
-- drop function if exists public.workspace_sim_status();
-- drop function if exists public.workspace_sim_stop();
-- drop function if exists public.workspace_sim_start(int, int);
-- drop function if exists public.workspace_cancel_invite(uuid);
-- drop function if exists public.workspace_remove_member(uuid);
-- drop function if exists public.workspace_set_member_role(uuid, text);
-- drop function if exists public.workspace_invite(text, text);
-- drop function if exists public.workspace_revoke_ingest_key(uuid);
-- drop function if exists public.workspace_create_ingest_key(text);
-- drop function if exists public.workspace_rename(text);
-- drop function if exists public.workspace_bootstrap();
-- drop function if exists public.my_workspace();
-- drop function if exists public._yf_ws_admin_gate();
-- drop function if exists public._yf_ws_refuse(text, text);
-- drop function if exists public._yf_my_site();
-- drop function if exists public._yf_provision_workspace(uuid, text);
--
-- -- yf_can_read_site: back to 0009's two-branch version, or gone.
-- do $$
-- begin
--   if to_regprocedure('public.yf_demo_site()') is not null then
--     execute $f$
--       create or replace function public.yf_can_read_site(p_site text)
--       returns boolean language plpgsql stable security definer
--       set search_path = '' as $body$
--       begin
--         if p_site is null then return false; end if;
--         if public.yf_is_demo_site(p_site) and p_site = public.yf_demo_site() then
--           return true;
--         end if;
--         return public.yf_has_role('operator', p_site);
--       end $body$ $f$;
--   else
--     execute 'drop function if exists public.yf_can_read_site(text)';
--   end if;
-- end $$;
--
-- drop function if exists public.yf_ingest_site();
-- drop function if exists public.yf_ingest_key_hash(text);
-- drop function if exists public.yf_ingest_key();
-- drop function if exists public.yf_is_workspace_site(text);
--
-- drop table if exists public.workspace_sims;
-- drop table if exists public.workspace_invites;
-- drop table if exists public.ingest_keys;
-- drop table if exists public.workspaces;
--
-- -- On a project WITHOUT 0009 the anon grants on the seven fleet tables
-- -- were introduced by this file; take them back. (With 0009 present they
-- -- are 0009's grants and must stay.)
-- -- revoke select, insert, update on public.robots, public.alerts,
-- --   public.incidents, public.missions, public.robot_telemetry,
-- --   public.maintenance_findings, public.commands from anon;
--
-- select 'ROLLED BACK 0019: workspaces removed' as result;
-- ============================================================
