# Yantrika Cloud workspaces — the self-serve contract (v0.13)

This is the spec every component codes against for the hosted, self-serve
platform at yantrika.ai: a visitor creates an account and, with no admin
involved, gets a **workspace** (their own `site_id`), an **admin** role in
it, **ingest keys** to connect real robots, and a one-click **simulated
fleet** so the console is never empty. Everything here is additive and
OPT-IN (`supabase/0019_workspaces.sql`); a deployment that never applies it
behaves exactly as v0.12 did.

Design rule, inherited from 0009: **identity for machines is a bearer
secret presented in a request header, resolved by one SQL function to
exactly one `site_id`, and every policy is pinned to that one value.**
The sandbox token (`x-yf-demo-token` → `yf_demo_site()`) and the ingest
key (`x-yf-ingest-key` → `yf_ingest_site()`) are the same mechanism with a
different namespace (`DEMO-*` vs `WS-*`).

## 1. Identity and namespaces

| Caller | Credential | Resolves to | Can |
|---|---|---|---|
| Signed-in person | Supabase Auth JWT (`Authorization: Bearer`) | `user_roles` rows (0007) | whatever their role allows at their sites |
| Robot connector / simulator for a workspace | anon key + `x-yf-ingest-key: yk_<64 hex>` | exactly one `WS-*` site via `yf_ingest_site()` | read/insert/update the seven fleet tables **at that site only** |
| Marketing sandbox visitor | anon key + `x-yf-demo-token` (0009) | exactly one `DEMO-*` site | unchanged |

* Workspace site ids are `WS-<8 lowercase hex>` (`yf_is_workspace_site(text)`).
* Ingest keys are `yk_` + 64 lowercase hex (two v4 UUIDs of entropy). Only
  the SHA-256 hex digest is stored (`ingest_keys.key_hash`); the plaintext
  is returned exactly once, by the RPC that created it.
* Because `robots.id` is a global primary key, every row a workspace writer
  creates is **namespaced with the site id**: robot `AMR-01` of `WS-1a2b3c4d`
  is stored as `WS-1a2b3c4d-AMR-01` (and the driver's own fleet as
  `WS-1a2b3c4d-R01`). The console strips `<site>-` for display.
  `yantrasim --supabase` and `yantrabridge` do this automatically when an
  ingest key is configured.

## 2. Schema (`0019_workspaces.sql`, OPT-IN, requires 0007)

```
workspaces(site_id text pk, name text, owner_id uuid null → auth.users,
           plan text default 'free' check in ('free','team','enterprise'),
           created_at, updated_at)
ingest_keys(id uuid pk, site_id → workspaces, key_hash text unique,
            prefix text  -- first 12 chars of the plaintext, for display
            label text default 'default',
            kind text default 'integration' check in ('integration','sim'),
            created_by uuid null, created_at, expires_at null, revoked_at null)
workspace_invites(id uuid pk, site_id → workspaces, email text (lowercased),
            role text check in ('operator','engineer','manager','admin'),
            invited_by uuid null, created_at, accepted_at null)
workspace_sims(site_id text pk → workspaces, key_id uuid → ingest_keys,
            started_by uuid null, started_at, expires_at, robots int,
            stopped_at null)
```

Grants: **anon has no access to any of the four tables.** `authenticated`
may `select` from `workspaces` where `yf_has_role('operator', site_id)`;
everything else goes through the SECURITY DEFINER RPCs below.

Trigger: `after insert on auth.users` → `public.yf_handle_new_user()`:
creates `WS-<hex>` named `"<email local part>'s workspace"`, inserts
`user_roles(user_id, site_id, 'admin')`, then consumes every
`workspace_invites` row for that email (inserts the invited roles, stamps
`accepted_at`).

Policies on the seven fleet tables (`robots, alerts, incidents, commands,
missions, robot_telemetry, maintenance_findings`), `to anon`, named
`ingest_read` / `ingest_insert` / `ingest_update`:
`using (public.yf_is_workspace_site(site_id) and site_id = public.yf_ingest_site())`
with the same predicate in `with check`. Column grants mirror 0009 (anon:
`select, insert, update` on robots/incidents/missions/robot_telemetry/
maintenance_findings; `select, insert` + `update (ack)` on alerts;
`select, insert` + `update (status, decided_by, decided_at, note,
executed_at)` on commands). No DELETE anywhere; `fleet_meta` stays
off-limits (no `site_id`), so workspace writers **never write fleet_meta**.

## 3. RPCs (all `security definer`, `set search_path = ''`)

Every RPC returns a single `jsonb` object with `ok: true|false`; failures
carry `reason` (a short snake_case code) and `error` (a sentence). Role
checks use 0007's `yf_has_role(min_role, site)`. "admin" below means admin
**at that workspace**.

| RPC | Who | Returns |
|---|---|---|
| `my_workspace()` | authenticated | `{ok, site_id, name, plan, role, owner, owner_id, created_at, keys:[{id,prefix,label,kind,created_at,expires_at}], sim:{running,expires_at,robots,started_at}, members:[{user_id,email,role,granted_at}] (admin only, else []), invites:[{id,email,role,created_at}] (admin only, else [])}`. With no role anywhere: `{ok:true, site_id:null}`. Picks the site where the caller is owner, else their highest role, else oldest grant. For a legacy site (`BLR-DC1`) with no `workspaces` row, `name = site_id`, `plan = 'self-hosted'`, `keys/sim` empty. |
| `workspace_bootstrap()` | authenticated | creates the caller's workspace **only if they have no `user_roles` row at all** (same logic as the trigger — exists for accounts created before 0019), then returns `my_workspace()`. |
| `workspace_rename(p_name text)` | admin | `{ok, name}`; 1–60 chars, trimmed. |
| `workspace_create_ingest_key(p_label text default 'default')` | admin | `{ok, id, key, prefix, label}` — `key` is the plaintext, shown once. Max 10 active `integration` keys per site → `{ok:false, reason:'too_many_keys'}`. |
| `workspace_revoke_ingest_key(p_id uuid)` | admin | `{ok}`; idempotent. |
| `workspace_invite(p_email text, p_role text)` | admin | `{ok, status:'added'|'invited', email, role}`. If `auth.users` has that email → upsert `user_roles`; else insert/refresh an invite. Cannot demote/remove the owner. |
| `workspace_set_member_role(p_user_id uuid, p_role text)` | admin | `{ok}`; refuses the owner → `{ok:false, reason:'owner'}`. |
| `workspace_remove_member(p_user_id uuid)` | admin | `{ok}`; refuses the owner. |
| `workspace_cancel_invite(p_id uuid)` | admin | `{ok}`. |
| `workspace_sim_start(p_minutes int default 240, p_robots int default 8)` | admin | revokes any previous `sim`-kind key for the site, mints a new one with `expires_at = now()+p_minutes` (clamped 5..1440; robots clamped 2..20), upserts `workspace_sims`, returns `{ok, site_id, key, expires_at, robots}`. |
| `workspace_sim_stop()` | admin | revokes sim keys, stamps `stopped_at`, returns `{ok, site_id}` (`site_id` lets the door SIGTERM the right local driver). |
| `workspace_sim_status()` | operator+ | `{ok, site_id, running, expires_at, robots, started_at}` (`running` = not stopped and `expires_at > now()`). |
| `workspace_purge_fleet()` | admin | deletes every row of the seven fleet tables where `site_id` = the caller's workspace; returns `{ok, deleted:{robots:n, ...}}`. Refuses `DEMO-*`/legacy sites that have no `workspaces` row. |

Grants: `execute` on all of the above to `authenticated, service_role`;
revoked from `public, anon`.

## 4. The door — `/api/workspace/` (yantraops sandbox-serve)

The same stdlib HTTP service that mints marketing sandboxes gains three
routes. Every one requires the person's own Supabase JWT in
`Authorization: Bearer <jwt>`; the door **forwards that JWT to PostgREST
unchanged** (apikey = anon key) so the RPCs enforce the role — the door
holds no privilege of its own.

| Route | Does | Answers |
|---|---|---|
| `POST /api/workspace/sim/start` (JSON body `{minutes?, robots?}`, both optional and clamped server-side) | calls `workspace_sim_start`; spawns `yantraops sandbox-drive --site WS-… --auth ingest` with the key in env `YANTRAOPS_INGEST_KEY`; records it in the registry with `kind:'workspace'` | `201 {ok, site_id, expires_at, robots}`; `401` no/invalid JWT; `403` RPC refused (not admin); `429 {reason:'ceiling'|'rate_limited'|'busy', retry_after}`; `502` backend error; `503` RPC absent (0019 not applied) |
| `POST /api/workspace/sim/stop` | calls `workspace_sim_stop`, SIGTERMs the local driver, drops the registry row | `200 {ok, site_id}` |
| `GET /api/workspace/sim/status` | calls `workspace_sim_status`; adds `driver_alive` from the registry | `200 {ok, site_id, running, expires_at, robots, started_at, driver_alive}` |

Ceilings: `--workspace-max-live` (default 12, env `YANTRAOPS_WORKSPACE_MAX`)
counts live `kind:'workspace'` registry rows separately from sandboxes.
Per-IP rate limit 10 per 15 minutes on the start route. nginx proxies
`/api/workspace/` to the same upstream as `/api/demo/`.

`sandbox-drive --auth ingest` differences from the demo driver: header
`x-yf-ingest-key`, site prefix `WS-`, robot ids `<site>-R01…`, no history
seeding, `session_live()` is "the last write was not refused" (a revoked
key makes RLS answer 401/403 and the driver exits).

## 5. Console behaviour

* `?mode=demo` — pure local mock data, no backend calls, no sign-in
  prompt, tour on; banner with *Create free account* and *Start a live
  sandbox*.
* `?demo=<token>` — sandbox: `x-yf-demo-token` on every PostgREST call,
  no `fleet_meta` access, follower mode, countdown chip from
  `demo_session_info`, expiry modal with sign-up CTA.
* signed in — `my_workspace()` (falls back to `workspace_bootstrap()` when
  `site_id` is null; if the RPC does not exist, legacy behaviour): the
  workspace's `site_id` scopes every query (`site_id=eq.<site>`), the
  header shows the workspace name, the **Workspace** view manages keys,
  members, the simulated fleet and integration snippets, and an empty
  fleet shows a *Get started* card instead of charts.

## 6. Copilot

`POST /ask` accepts `{question, site?}` and two optional headers the
console forwards so the copilot **reads as the asker**: `X-YF-User-Token`
(the person's Supabase JWT) and `X-YF-Demo-Token` (a sandbox token). For
that request the toolbox sends them to PostgREST (`Authorization: Bearer
<jwt>` or `x-yf-demo-token`) and filters by `site_id=eq.<site>`; RLS, not
the copilot, decides what is visible. Without them, behaviour is unchanged.

## 7. Implementation notes and deviations (as built)

Everything above is implemented as written, with these deliberate
differences. Each one is recorded because a reader of only the spec would
otherwise be surprised.

* **`yf_has_role` is redefined by 0019** (same signature and grants).
  0007 makes an `admin` role at *any* site global. The sign-up trigger
  gives every stranger `admin` at their own `WS-*` site, which under 0007's
  clause would make each new account an admin of the legacy fleet and of
  every other tenant. 0019 therefore confines an admin role held at a
  `WS-*` site to that workspace; an admin at a legacy site (the operator's
  own staff) is unchanged. Section 3's "role checks use 0007's
  `yf_has_role`" holds, with this one narrowing.
* **Thirteen RPCs, not fourteen**: the table in section 3 lists thirteen
  and that is what exists. `demo_session_info(p_token)` (0009) is the
  console's fourteenth call and is unchanged.
* **Refusals are HTTP 200 envelopes**: `{ok:false, reason, error}`.
  `reason` is one of `unauthenticated`, `no_workspace`, `forbidden`,
  `not_workspace` (a legacy/demo site has no `workspaces` row),
  `owner`, `not_member`, `invalid_name`, `invalid_role`, `invalid_email`,
  `too_many_keys`. The door maps `unauthenticated` to 401 and every other
  refusal to 403 with the reason passed through.
* **`my_workspace()`** also returns `owner_id` (the workspace owner's user
  id, so the console can compare it with `member.user_id`).
* **Door status codes**: an invalid or expired JWT is 401
  `{reason:'unauthenticated'}`; PostgREST's `PGRST202` (function not found)
  is 503 `{reason:'not_enabled'}`; `sim/start` reads `{minutes?, robots?}`
  (clamped 5..1440 / 2..20) and ignores any other field, including a
  caller-supplied site. The ingest key never appears in any response.
* **Copilot with a site** skips the `fleet_meta` heartbeat entirely
  (it has no `site_id` column, so `site_id=eq.<site>` would be a PostgREST
  error, and a sandbox/ingest credential cannot read it). Throughput and
  `sim_min` therefore read null in a site-scoped answer. `site` must be a
  short slug (`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`, else 422); malformed
  `X-YF-User-Token` / `X-YF-Demo-Token` values are dropped, not forwarded.
* **Writers** (`yantrasim --supabase`, `yantrabridge` incl. `import`):
  `--ingest-key` / `YANTRA_INGEST_KEY` plus `--site` / `YANTRA_SITE_ID`
  (must be `WS-<8 hex>`; a malformed key or a non-workspace site exits 2
  before any request). Approved commands are polled per site and the
  `<site>-` prefix is stripped before routing to the robot's VDA serial.
