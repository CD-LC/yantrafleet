"""Tests for self-serve workspaces (supabase/0019 + yantraops' ingest-key
driver + the /api/workspace/ door), per docs/WORKSPACES.md.

Every test runs against ``e2e/fakerest.py`` in RBAC mode on a 127.0.0.1
ephemeral port — the same stand-in the sandbox suite uses, extended with
the 0019 emulation (ingest identity, workspace stores, the 13 RPCs and the
sign-up trigger). No cloud, no network egress, no mocking of our own
behaviour.

The first half asserts the isolation promises directly, because an ingest
key is the second credential this platform hands to a machine on the open
internet: a key reaches exactly the seven fleet tables of exactly one
WS-* site, never a legacy or DEMO site, never a privileged table, never a
DELETE — and a revoked, expired or malformed key is plain anon, which 0007
gives nothing at all.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from yantraops import sandbox as sb
from yantraops import sandbox_http as sh
from yantraops.__main__ import build_parser
from yantraops.orchestrator import load_fakerest, repo_root

ANON_KEY = "anon-publishable-key"
SERVICE_KEY = "sk-test-service"

OWNER = "ana@example.com"          # signs up -> owner + admin of her workspace
OPERATOR = "carl@example.com"      # pre-0019 account, operator-only, no workspace
STRANGER = "zed@example.com"       # signed in, no role anywhere


# --------------------------------------------------------------------------
# Fixtures + helpers
# --------------------------------------------------------------------------

@pytest.fixture()
def fakerest():
    """FakePostgREST in RBAC mode with a legacy site and a demo sandbox
    already populated, so "cannot reach another site" has targets."""
    mod = load_fakerest(repo_root())
    fake = mod.FakePostgREST(
        tables={
            "robots": [
                {"id": "AMR-01", "vendor": "MiR", "status": "active",
                 "battery": 88.0, "pos": [3, 4], "speed": 1.1,
                 "health": 97.0, "motor_temp": 44.0, "tasks_done": 12,
                 "site_id": "BLR-DC1"},
            ],
            "alerts": [
                {"id": "al-real-1", "sev": "warn", "msg": "real site alert",
                 "src": "AMR-01", "tlabel": "10:00", "ack": False,
                 "site_id": "BLR-DC1"},
            ],
            "fleet_meta": [{"id": 1, "writer_id": "real", "sim_min": 3}],
        },
        rbac=True, service_key=SERVICE_KEY, anon_key=ANON_KEY)
    fake.mod = mod
    base = fake.start()
    fake.base_url = base
    try:
        yield fake
    finally:
        fake.stop()


@pytest.fixture()
def owner(fakerest):
    """A fresh sign-up: the trigger provisioned a workspace + admin role."""
    signup = fakerest.simulate_signup(OWNER)
    return {"site": signup["site_id"], "user_id": signup["user_id"],
            "jwt": fakerest.mod.make_session_jwt(OWNER)}


@pytest.fixture()
def operator(fakerest, owner):
    """A pre-0019 account (exists in auth.users, no workspace of its own)
    that the owner added as an operator — the shape every non-admin
    refusal test needs."""
    fakerest.auth_users[OPERATOR] = fakerest.mod.test_user_id(OPERATOR)
    reply = _rpc(fakerest.base_url, "workspace_invite",
                 {"p_email": OPERATOR, "p_role": "operator"}, owner["jwt"])
    assert reply == {"ok": True, "status": "added", "email": OPERATOR,
                     "role": "operator"}
    return {"site": owner["site"], "jwt": fakerest.mod.make_session_jwt(OPERATOR),
            "user_id": fakerest.mod.test_user_id(OPERATOR)}


@pytest.fixture()
def state_file(tmp_path):
    return tmp_path / "sandboxes.json"


def _headers(jwt: str | None = None, ingest_key: str | None = None,
             demo_token: str | None = None, key: str = ANON_KEY) -> dict[str, str]:
    h = {"apikey": key, "Authorization": f"Bearer {jwt or key}",
         "Content-Type": "application/json"}
    if ingest_key:
        h[sb.INGEST_KEY_HEADER] = ingest_key
    if demo_token:
        h[sb.DEMO_TOKEN_HEADER] = demo_token
    return h


def _rpc(base_url: str, fn: str, args: dict | None = None,
         jwt: str | None = None, **kw):
    resp = httpx.post(f"{base_url}/rest/v1/rpc/{fn}", json=args or {},
                      headers=_headers(jwt, **kw), timeout=5.0)
    assert resp.status_code == 200, (fn, resp.status_code, resp.text)
    return resp.json()


def _get(base_url: str, table: str, **kw):
    params = kw.pop("params", None)
    return httpx.get(f"{base_url}/rest/v1/{table}", params=params,
                     headers=_headers(**kw), timeout=5.0)


def _post(base_url: str, table: str, body, params=None, merge=False, **kw):
    headers = _headers(**kw)
    if merge:
        headers["Prefer"] = "resolution=merge-duplicates,return=minimal"
    return httpx.post(f"{base_url}/rest/v1/{table}", json=body, params=params,
                      headers=headers, timeout=5.0)


def _robot(site: str, n: int = 1, **extra) -> dict:
    return {"id": f"{site}-R{n:02d}", "vendor": "MiR", "status": "idle",
            "battery": 55.0, "pos": [1, 2], "speed": 0, "site_id": site,
            **extra}


def _make_key(fakerest, jwt: str, label: str = "default") -> dict:
    reply = _rpc(fakerest.base_url, "workspace_create_ingest_key",
                 {"p_label": label}, jwt)
    assert reply["ok"] is True, reply
    return reply


# ==========================================================================
# Provisioning: sign-up trigger, bootstrap, my_workspace
# ==========================================================================

def test_signup_provisions_a_workspace_and_an_admin_role(fakerest, owner):
    assert sb.is_workspace_site(owner["site"])
    me = _rpc(fakerest.base_url, "my_workspace", jwt=owner["jwt"])
    assert me["ok"] is True
    assert me["site_id"] == owner["site"]
    assert me["name"] == "ana's workspace"
    assert me["plan"] == "free"
    assert me["role"] == "admin" and me["owner"] is True
    assert me["keys"] == [] and me["invites"] == []
    assert me["sim"] == {"running": False, "expires_at": None,
                         "robots": None, "started_at": None}
    assert [m["email"] for m in me["members"]] == [OWNER]
    assert me["members"][0]["role"] == "admin"
    # The trigger wrote a real role grant: the workspace's rows are visible
    # to the owner's plain session token through 0007's rbac_read.
    _post(fakerest.base_url, "robots", [_robot(owner["site"])], key=SERVICE_KEY)
    rows = _get(fakerest.base_url, "robots", jwt=owner["jwt"]).json()
    assert [r["id"] for r in rows] == [f"{owner['site']}-R01"]


def test_my_workspace_reports_no_site_for_a_roleless_account(fakerest):
    jwt = fakerest.mod.make_session_jwt(STRANGER)
    assert _rpc(fakerest.base_url, "my_workspace", jwt=jwt) == {
        "ok": True, "site_id": None}
    # ...and nothing at all for anon.
    assert _rpc(fakerest.base_url, "my_workspace")["reason"] == "unauthenticated"


def test_bootstrap_provisions_once_and_is_idempotent(fakerest):
    jwt = fakerest.mod.make_session_jwt(STRANGER)
    first = _rpc(fakerest.base_url, "workspace_bootstrap", jwt=jwt)
    assert first["ok"] is True and sb.is_workspace_site(first["site_id"])
    assert first["role"] == "admin" and first["owner"] is True
    assert first["name"] == "zed's workspace"
    second = _rpc(fakerest.base_url, "workspace_bootstrap", jwt=jwt)
    assert second["site_id"] == first["site_id"]
    assert len(fakerest.workspaces) == 1


def test_bootstrap_never_mints_a_second_workspace_for_a_role_holder(
        fakerest, owner, operator):
    """An operator at somebody else's workspace already has a role, so
    bootstrap must NOT hand them a workspace of their own."""
    reply = _rpc(fakerest.base_url, "workspace_bootstrap", jwt=operator["jwt"])
    assert reply["site_id"] == owner["site"] and reply["role"] == "operator"
    assert reply["owner"] is False
    assert reply["members"] == [] and reply["invites"] == []   # admin-only
    assert len(fakerest.workspaces) == 1


def test_legacy_site_reports_as_self_hosted(fakerest):
    """A pre-0019 admin of BLR-DC1 with no workspaces row."""
    jwt = fakerest.mod.make_test_jwt("ops-lead@example.com", "admin", "BLR-DC1")
    me = _rpc(fakerest.base_url, "my_workspace", jwt=jwt)
    assert me["site_id"] == "BLR-DC1" and me["name"] == "BLR-DC1"
    assert me["plan"] == "self-hosted" and me["keys"] == []
    assert me["sim"]["running"] is False
    # ...and the workspace-only RPCs refuse rather than guess.
    for fn in ("workspace_sim_start", "workspace_purge_fleet",
               "workspace_create_ingest_key", "workspace_rename"):
        args = {"p_name": "x"} if fn == "workspace_rename" else {}
        reply = _rpc(fakerest.base_url, fn, args, jwt)
        assert reply["ok"] is False and reply["reason"] == "not_workspace", fn


def test_invites_are_consumed_at_signup(fakerest, owner):
    reply = _rpc(fakerest.base_url, "workspace_invite",
                 {"p_email": "  Bea@Example.com ", "p_role": "manager"},
                 owner["jwt"])
    assert reply == {"ok": True, "status": "invited", "email": "bea@example.com",
                     "role": "manager"}
    me = _rpc(fakerest.base_url, "my_workspace", jwt=owner["jwt"])
    assert [i["email"] for i in me["invites"]] == ["bea@example.com"]
    signup = fakerest.simulate_signup("bea@example.com")
    bea = fakerest.mod.make_session_jwt("bea@example.com")
    mine = _rpc(fakerest.base_url, "my_workspace", jwt=bea)
    # Bea owns her own workspace (picked first), and holds manager at Ana's.
    assert mine["site_id"] == signup["site_id"] and mine["owner"] is True
    assert fakerest.role_grants[(signup["user_id"], owner["site"])]["role"] == "manager"
    me = _rpc(fakerest.base_url, "my_workspace", jwt=owner["jwt"])
    assert me["invites"] == []
    assert {m["email"]: m["role"] for m in me["members"]} == {
        OWNER: "admin", "bea@example.com": "manager"}


# ==========================================================================
# Role checks: every mutating RPC is admin-at-this-workspace
# ==========================================================================

@pytest.mark.parametrize("fn, args", [
    ("workspace_rename", {"p_name": "Hijacked"}),
    ("workspace_create_ingest_key", {"p_label": "x"}),
    ("workspace_revoke_ingest_key", {"p_id": str(uuid.uuid4())}),
    ("workspace_invite", {"p_email": "x@example.com", "p_role": "admin"}),
    ("workspace_set_member_role", {"p_user_id": str(uuid.uuid4()),
                                   "p_role": "admin"}),
    ("workspace_remove_member", {"p_user_id": str(uuid.uuid4())}),
    ("workspace_cancel_invite", {"p_id": str(uuid.uuid4())}),
    ("workspace_sim_start", {"p_minutes": 30, "p_robots": 4}),
    ("workspace_sim_stop", {}),
    ("workspace_purge_fleet", {}),
])
def test_non_admin_rpcs_are_refused(fakerest, owner, operator, fn, args):
    before = (dict(fakerest.workspaces), dict(fakerest.ingest_keys),
              dict(fakerest.role_grants), len(fakerest.tables["robots"]))
    reply = _rpc(fakerest.base_url, fn, args, operator["jwt"])
    assert reply["ok"] is False and reply["reason"] == "forbidden", reply
    assert "admin" in reply["error"]
    # Nothing moved.
    assert (dict(fakerest.workspaces), dict(fakerest.ingest_keys),
            dict(fakerest.role_grants), len(fakerest.tables["robots"])) == before
    # anon is refused one step earlier, and so is a role-less account.
    assert _rpc(fakerest.base_url, fn, args)["reason"] == "unauthenticated"
    nobody = fakerest.mod.make_session_jwt(STRANGER)
    assert _rpc(fakerest.base_url, fn, args, nobody)["reason"] == "no_workspace"


def test_operator_may_read_sim_status_but_not_start_it(fakerest, owner, operator):
    status = _rpc(fakerest.base_url, "workspace_sim_status", jwt=operator["jwt"])
    assert status["ok"] is True and status["running"] is False
    assert status["site_id"] == owner["site"]


def test_owner_cannot_be_demoted_or_removed(fakerest, owner, operator):
    for fn, args in (("workspace_set_member_role",
                      {"p_user_id": owner["user_id"], "p_role": "operator"}),
                     ("workspace_remove_member", {"p_user_id": owner["user_id"]}),
                     ("workspace_invite", {"p_email": OWNER, "p_role": "operator"})):
        reply = _rpc(fakerest.base_url, fn, args, owner["jwt"])
        assert reply["ok"] is False and reply["reason"] == "owner", fn
    assert fakerest.role_grants[(owner["user_id"], owner["site"])]["role"] == "admin"
    # A plain member can be changed and removed.
    assert _rpc(fakerest.base_url, "workspace_set_member_role",
                {"p_user_id": operator["user_id"], "p_role": "manager"},
                owner["jwt"]) == {"ok": True}
    assert fakerest.role_grants[(operator["user_id"], owner["site"])]["role"] == "manager"
    assert _rpc(fakerest.base_url, "workspace_remove_member",
                {"p_user_id": operator["user_id"]}, owner["jwt"]) == {"ok": True}
    assert (operator["user_id"], owner["site"]) not in fakerest.role_grants
    assert _rpc(fakerest.base_url, "workspace_set_member_role",
                {"p_user_id": operator["user_id"], "p_role": "admin"},
                owner["jwt"])["reason"] == "not_member"


def test_rename_validates_and_trims(fakerest, owner):
    assert _rpc(fakerest.base_url, "workspace_rename", {"p_name": "  Dock 7  "},
                owner["jwt"]) == {"ok": True, "name": "Dock 7"}
    assert fakerest.workspaces[owner["site"]]["name"] == "Dock 7"
    for bad in ("", "   ", "x" * 61, None):
        reply = _rpc(fakerest.base_url, "workspace_rename", {"p_name": bad},
                     owner["jwt"])
        assert reply["ok"] is False and reply["reason"] == "invalid_name"


# ==========================================================================
# Ingest keys: minting, the key as a credential, revocation
# ==========================================================================

def test_key_is_minted_once_and_only_its_hash_is_stored(fakerest, owner):
    minted = _make_key(fakerest, owner["jwt"], label="conveyor PLC")
    assert set(minted) == {"ok", "id", "key", "prefix", "label"}
    assert sb.valid_ingest_key(minted["key"])
    assert minted["prefix"] == minted["key"][:12] and minted["label"] == "conveyor PLC"
    stored = fakerest.ingest_keys[minted["id"]]
    assert minted["key"] not in json.dumps(stored)
    assert stored["key_hash"] == fakerest.mod._ingest_key_hash(minted["key"])
    # my_workspace lists the key WITHOUT the plaintext.
    me = _rpc(fakerest.base_url, "my_workspace", jwt=owner["jwt"])
    assert [k["prefix"] for k in me["keys"]] == [minted["prefix"]]
    assert minted["key"] not in json.dumps(me)
    assert me["keys"][0]["kind"] == "integration"


def test_integration_keys_are_capped_at_ten(fakerest, owner):
    for i in range(10):
        _make_key(fakerest, owner["jwt"], label=f"k{i}")
    reply = _rpc(fakerest.base_url, "workspace_create_ingest_key", {}, owner["jwt"])
    assert reply["ok"] is False and reply["reason"] == "too_many_keys"
    # Revoking one frees a slot.
    victim = next(iter(fakerest.ingest_keys))
    assert _rpc(fakerest.base_url, "workspace_revoke_ingest_key",
                {"p_id": victim}, owner["jwt"]) == {"ok": True}
    assert _make_key(fakerest, owner["jwt"])["ok"] is True


def test_key_reads_and_writes_its_own_workspace_only(fakerest, owner):
    site = owner["site"]
    key = _make_key(fakerest, owner["jwt"])["key"]
    # Writes land, stamped with the site, and are readable back by the key
    # — and by the owner's session — but by nobody without a credential.
    assert _post(fakerest.base_url, "robots", [_robot(site)],
                 ingest_key=key).status_code == 201
    seen = _get(fakerest.base_url, "robots", ingest_key=key).json()
    assert [r["id"] for r in seen] == [f"{site}-R01"]
    assert all(r["site_id"] == site for r in seen)
    assert _get(fakerest.base_url, "robots").json() == []
    assert [r["id"] for r in _get(fakerest.base_url, "robots",
                                  jwt=owner["jwt"]).json()] == [f"{site}-R01"]
    # The legacy fleet and the real alerts are invisible to the key.
    for table in ("robots", "alerts", "incidents"):
        rows = _get(fakerest.base_url, table, ingest_key=key).json()
        assert all(r["site_id"] == site for r in rows), table
    # Upsert (merge) and column-limited updates work inside the site...
    assert _post(fakerest.base_url, "robots", [_robot(site, status="active")],
                 params={"on_conflict": "id"}, merge=True, ingest_key=key,
                 ).status_code == 201
    assert next(r for r in fakerest.tables["robots"]
                if r["id"] == f"{site}-R01")["status"] == "active"
    assert _post(fakerest.base_url, "alerts",
                 [{"id": f"{site}-A1", "sev": "warn", "msg": "m", "src": f"{site}-R01",
                   "tlabel": "t", "ack": False, "site_id": site}],
                 ingest_key=key).status_code == 201
    ok = httpx.patch(f"{fakerest.base_url}/rest/v1/alerts",
                     params={"id": f"eq.{site}-A1"}, json={"ack": True},
                     headers=_headers(ingest_key=key), timeout=5.0)
    assert ok.status_code == 204
    assert next(a for a in fakerest.tables["alerts"]
                if a["id"] == f"{site}-A1")["ack"] is True
    # ...but an alert's text is not the key's to rewrite (column grant).
    bad = httpx.patch(f"{fakerest.base_url}/rest/v1/alerts",
                      params={"id": f"eq.{site}-A1"}, json={"msg": "rewritten"},
                      headers=_headers(ingest_key=key), timeout=5.0)
    assert bad.status_code == 403


def test_key_cannot_write_or_read_another_site_or_a_demo_site(fakerest, owner):
    site = owner["site"]
    key = _make_key(fakerest, owner["jwt"])["key"]
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        demo = api.mint(seed_robots=2)
    other = fakerest.simulate_signup("rival@example.com")["site_id"]

    for target in ("BLR-DC1", demo.site_id, other):
        resp = _post(fakerest.base_url, "robots",
                     [{"id": f"{target}-forged", "vendor": "MiR", "site_id": target}],
                     ingest_key=key)
        assert resp.status_code == 403, target
        assert "row-level security" in resp.text
        assert not [r for r in fakerest.tables["robots"] if r["id"] == f"{target}-forged"]
    # A row with no site_id takes 0005's column default (BLR-DC1): refused.
    resp = _post(fakerest.base_url, "robots", [{"id": "no-site", "vendor": "MiR"}],
                 ingest_key=key)
    assert resp.status_code == 403
    # No merge onto another site's primary key, no moving a row across sites.
    resp = _post(fakerest.base_url, "robots", [dict(_robot(site), id="AMR-01")],
                 params={"on_conflict": "id"}, merge=True, ingest_key=key)
    assert resp.status_code == 403
    assert next(r for r in fakerest.tables["robots"] if r["id"] == "AMR-01")["site_id"] == "BLR-DC1"
    _post(fakerest.base_url, "robots", [_robot(site)], ingest_key=key)
    moved = httpx.patch(f"{fakerest.base_url}/rest/v1/robots",
                        params={"id": f"eq.{site}-R01"}, json={"site_id": "BLR-DC1"},
                        headers=_headers(ingest_key=key), timeout=5.0)
    assert moved.status_code == 403
    # The demo sandbox's robots are not readable with a key, and the key's
    # robots are not readable with the demo token.
    assert all(r["site_id"] == site for r in
               _get(fakerest.base_url, "robots", ingest_key=key).json())
    assert all(r["site_id"] == demo.site_id for r in
               _get(fakerest.base_url, "robots", demo_token=demo.token).json())


def test_key_cannot_touch_privileged_tables_or_delete(fakerest, owner):
    site = owner["site"]
    key = _make_key(fakerest, owner["jwt"])["key"]
    for table in ("fleet_meta", "user_roles", "workspaces", "ingest_keys",
                  "workspace_invites", "workspace_sims", "app_settings",
                  "demo_sessions"):
        resp = _get(fakerest.base_url, table, ingest_key=key)
        assert resp.status_code >= 400 or resp.json() == [], table
        resp = _post(fakerest.base_url, table, [{"id": 1, "site_id": site}],
                     ingest_key=key)
        assert resp.status_code >= 400, table
    assert fakerest.tables["fleet_meta"] == [
        {"id": 1, "writer_id": "real", "sim_min": 3}]
    # The RPCs that need a person refuse a key outright.
    for fn in ("my_workspace", "workspace_create_ingest_key",
               "workspace_sim_start", "workspace_purge_fleet"):
        assert _rpc(fakerest.base_url, fn, {}, ingest_key=key)["reason"] == \
            "unauthenticated", fn
    # No DELETE, not even inside its own site.
    _post(fakerest.base_url, "robots", [_robot(site)], ingest_key=key)
    resp = httpx.request("DELETE", f"{fakerest.base_url}/rest/v1/robots",
                         params={"id": f"eq.{site}-R01"},
                         headers=_headers(ingest_key=key), timeout=5.0)
    assert resp.status_code >= 400
    assert any(r["id"] == f"{site}-R01" for r in fakerest.tables["robots"])


def test_revoked_expired_and_malformed_keys_see_nothing(fakerest, owner):
    site = owner["site"]
    minted = _make_key(fakerest, owner["jwt"])
    key = minted["key"]
    _post(fakerest.base_url, "robots", [_robot(site)], ingest_key=key)
    assert _get(fakerest.base_url, "robots", ingest_key=key).json()

    for bogus in ("", "yk_", key[:-1], key.upper(), key.replace("yk_", "zz_"),
                  "yk_" + "0" * 64, key + "0"):
        assert _get(fakerest.base_url, "robots", ingest_key=bogus).json() == [], bogus
        resp = _post(fakerest.base_url, "robots", [_robot(site, 9)], ingest_key=bogus)
        assert resp.status_code in (401, 403), bogus

    assert _rpc(fakerest.base_url, "workspace_revoke_ingest_key",
                {"p_id": minted["id"]}, owner["jwt"]) == {"ok": True}
    assert _get(fakerest.base_url, "robots", ingest_key=key).json() == []
    resp = _post(fakerest.base_url, "robots", [_robot(site, 2)], ingest_key=key)
    assert resp.status_code in (401, 403)
    assert not [r for r in fakerest.tables["robots"] if r["id"] == f"{site}-R02"]
    # Revoking again, or revoking somebody else's id, is a quiet {ok}.
    assert _rpc(fakerest.base_url, "workspace_revoke_ingest_key",
                {"p_id": minted["id"]}, owner["jwt"]) == {"ok": True}
    assert _rpc(fakerest.base_url, "workspace_revoke_ingest_key",
                {"p_id": str(uuid.uuid4())}, owner["jwt"]) == {"ok": True}
    me = _rpc(fakerest.base_url, "my_workspace", jwt=owner["jwt"])
    assert me["keys"] == []

    # An expired key is as dead as a revoked one.
    fresh = _make_key(fakerest, owner["jwt"])
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    fakerest.ingest_keys[fresh["id"]]["expires_at"] = past.isoformat()
    assert _get(fakerest.base_url, "robots", ingest_key=fresh["key"]).json() == []
    # A key whose workspace vanished is dead too.
    again = _make_key(fakerest, owner["jwt"])
    fakerest.workspaces.pop(site)
    assert _get(fakerest.base_url, "robots", ingest_key=again["key"]).json() == []


def test_a_revoked_key_cannot_be_resurrected_by_the_key_holder(fakerest, owner):
    """The key holder is a machine: it has no RPC that mints or un-revokes."""
    key = _make_key(fakerest, owner["jwt"])["key"]
    for fn, args in (("workspace_create_ingest_key", {}),
                     ("workspace_sim_start", {}),
                     ("workspace_invite", {"p_email": "x@example.com",
                                           "p_role": "admin"})):
        reply = _rpc(fakerest.base_url, fn, args, ingest_key=key)
        assert reply["ok"] is False and reply["reason"] == "unauthenticated"
    assert len(fakerest.ingest_keys) == 1


# ==========================================================================
# The simulated fleet, via the RPCs
# ==========================================================================

def test_sim_start_status_stop_via_rpc(fakerest, owner):
    site = owner["site"]
    started = _rpc(fakerest.base_url, "workspace_sim_start",
                   {"p_minutes": 3, "p_robots": 99}, owner["jwt"])
    assert started["ok"] is True and started["site_id"] == site
    assert sb.valid_ingest_key(started["key"])
    assert started["robots"] == 20                      # clamped 2..20
    expires = sb._parse_ts(started["expires_at"])
    remaining = (expires - datetime.now(timezone.utc)).total_seconds()
    assert 4 * 60 < remaining <= 5 * 60                  # clamped 5..1440 min
    status = _rpc(fakerest.base_url, "workspace_sim_status", jwt=owner["jwt"])
    assert status["ok"] is True and status["running"] is True
    assert status["robots"] == 20 and status["expires_at"] == started["expires_at"]
    me = _rpc(fakerest.base_url, "my_workspace", jwt=owner["jwt"])
    assert me["sim"]["running"] is True
    assert [k["kind"] for k in me["keys"]] == ["sim"]
    # The sim key is a working ingest key for exactly this site.
    assert _post(fakerest.base_url, "robots", [_robot(site)],
                 ingest_key=started["key"]).status_code == 201

    # Restarting revokes the previous sim key and mints a new one.
    again = _rpc(fakerest.base_url, "workspace_sim_start", {}, owner["jwt"])
    assert again["key"] != started["key"] and again["robots"] == 8
    assert _get(fakerest.base_url, "robots", ingest_key=started["key"]).json() == []
    assert _get(fakerest.base_url, "robots", ingest_key=again["key"]).json()
    assert len([k for k in fakerest.ingest_keys.values()
                if k["kind"] == "sim" and not k["revoked_at"]]) == 1

    stopped = _rpc(fakerest.base_url, "workspace_sim_stop", jwt=owner["jwt"])
    assert stopped["ok"] is True and stopped["site_id"] == site
    status = _rpc(fakerest.base_url, "workspace_sim_status", jwt=owner["jwt"])
    assert status["running"] is False
    assert _get(fakerest.base_url, "robots", ingest_key=again["key"]).json() == []
    # Stopping twice is harmless.
    assert _rpc(fakerest.base_url, "workspace_sim_stop", jwt=owner["jwt"])["ok"] is True


def test_purge_fleet_deletes_only_the_callers_site(fakerest, owner):
    site = owner["site"]
    other = fakerest.simulate_signup("rival@example.com")["site_id"]
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        demo = api.mint(seed_robots=2)
    for s in (site, other):
        _post(fakerest.base_url, "robots", [_robot(s, 1), _robot(s, 2)], key=SERVICE_KEY)
        _post(fakerest.base_url, "robot_telemetry",
              [{"robot_id": f"{s}-R01", "ts": "2026-01-01T00:00:00Z",
                "battery": 1, "status": "idle", "site_id": s}], key=SERVICE_KEY)
    before = {t: [r for r in rows if r.get("site_id") != site]
              for t, rows in fakerest.tables.items()}

    reply = _rpc(fakerest.base_url, "workspace_purge_fleet", jwt=owner["jwt"])
    assert reply["ok"] is True and reply["site_id"] == site
    assert reply["deleted"]["robots"] == 2 and reply["deleted"]["robot_telemetry"] == 1
    assert set(reply["deleted"]) == {"robots", "alerts", "incidents", "missions",
                                     "robot_telemetry", "maintenance_findings",
                                     "commands"}
    for t, rows in fakerest.tables.items():
        assert not [r for r in rows if r.get("site_id") == site], t
        assert [r for r in rows if r.get("site_id") != site] == before[t], t
    assert len([r for r in fakerest.tables["robots"]
                if r["site_id"] == demo.site_id]) == 2
    assert any(r["id"] == "AMR-01" for r in fakerest.tables["robots"])
    # Purging an empty workspace is a zero-count success.
    assert _rpc(fakerest.base_url, "workspace_purge_fleet",
                jwt=owner["jwt"])["deleted"]["robots"] == 0


# ==========================================================================
# The driver in --auth ingest mode
# ==========================================================================

def _start_sim(fakerest, owner, robots: int = 3) -> dict:
    reply = _rpc(fakerest.base_url, "workspace_sim_start",
                 {"p_minutes": 10, "p_robots": robots}, owner["jwt"])
    assert reply["ok"] is True
    return reply


def test_driver_refuses_the_wrong_namespace_or_a_bad_key(fakerest, owner):
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        with pytest.raises(sb.SandboxError, match="non-workspace"):
            sb.SandboxDriver(api, "DEMO-ABCDEF012345", "yk_" + "a" * 64,
                             auth=sb.AUTH_INGEST)
        with pytest.raises(sb.SandboxError, match="non-workspace"):
            sb.SandboxDriver(api, "BLR-DC1", "yk_" + "a" * 64, auth=sb.AUTH_INGEST)
        with pytest.raises(sb.SandboxError, match="ingest key"):
            sb.SandboxDriver(api, owner["site"], "a" * 64, auth=sb.AUTH_INGEST)
        with pytest.raises(sb.SandboxError, match="non-demo"):
            sb.SandboxDriver(api, owner["site"], "a" * 64)        # demo mode
        with pytest.raises(sb.SandboxError, match="unknown --auth"):
            sb.SandboxDriver(api, owner["site"], "yk_" + "a" * 64, auth="service")
    with pytest.raises(sb.SandboxError):
        sb.DriverSession.from_rpc({"ok": True, "key": "yk_" + "a" * 64,
                                   "site_id": "BLR-DC1"})
    with pytest.raises(sb.SandboxError):
        sb.DriverSession.from_rpc({"ok": False, "reason": "forbidden"})


def test_driver_writes_namespaced_rows_only_at_its_site(fakerest, owner):
    site = owner["site"]
    sim = _start_sim(fakerest, owner, robots=3)
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        driver = sb.SandboxDriver(api, site, sim["key"], robots=3,
                                  interval=0.0, history_every=1,
                                  auth=sb.AUTH_INGEST)
        assert [r.robot_id for r in driver.sim.robots] == [
            f"{site}-R0{i}" for i in (1, 2, 3)]
        assert driver.adopt_live_fleet() == 0            # nothing seeded: fine
        counts = driver.tick_once()
        for _ in range(5):
            driver.tick_once()
    assert counts["robots"] == 3
    assert driver.session_live() is True and driver.refused is False
    mine = [r for r in fakerest.tables["robots"] if r["site_id"] == site]
    assert {r["id"] for r in mine} == {f"{site}-R0{i}" for i in (1, 2, 3)}
    for table in ("robots", "robot_telemetry", "missions", "alerts", "incidents"):
        for row in fakerest.tables[table]:
            if row.get("site_id") == site:
                ident = row.get("id") if table != "robot_telemetry" else row["robot_id"]
                assert str(ident).startswith(site) or str(ident).startswith("al-" + site), (table, row)
    # The legacy fleet is exactly as it was, and no fleet_meta was written.
    assert [r["id"] for r in fakerest.tables["robots"] if r["site_id"] == "BLR-DC1"] == ["AMR-01"]
    assert fakerest.tables["fleet_meta"] == [{"id": 1, "writer_id": "real", "sim_min": 3}]
    assert not any(p.endswith("/fleet_meta") for _m, p in fakerest.requests)


def test_driver_exits_when_its_key_is_revoked(fakerest, owner):
    site = owner["site"]
    sim = _start_sim(fakerest, owner, robots=2)
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        driver = sb.SandboxDriver(api, site, sim["key"], robots=2,
                                  interval=0.0, auth=sb.AUTH_INGEST)
        assert driver.run(ticks=2) == 2
        before = len([r for r in fakerest.tables["robot_telemetry"]
                      if r["site_id"] == site])
        # The admin presses stop: the key is revoked server-side.
        _rpc(fakerest.base_url, "workspace_sim_stop", jwt=owner["jwt"])
        errors: list[Exception] = []
        done = driver.run(ticks=50, on_error=errors.append)
    assert done < 50, "the driver must stop spinning on a revoked key"
    assert errors and all(e.status in (401, 403) for e in errors)
    assert driver.refused is True and driver.session_live() is False
    after = len([r for r in fakerest.tables["robot_telemetry"] if r["site_id"] == site])
    assert after == before


def test_drive_command_reads_the_key_from_the_environment(fakerest, owner,
                                                          monkeypatch):
    sim = _start_sim(fakerest, owner, robots=2)
    monkeypatch.setenv(sb.INGEST_KEY_ENV, sim["key"])
    monkeypatch.delenv(sb.DEMO_TOKEN_ENV, raising=False)
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        rc = sb.run_sandbox_drive(fakerest.base_url, ANON_KEY, owner["site"],
                                  robots=2, interval=0.0, ticks=3, api=api,
                                  auth=sb.AUTH_INGEST)
    assert rc == sb.EXIT_OK
    moved = [r for r in fakerest.tables["robots"] if r["site_id"] == owner["site"]]
    assert {r["id"] for r in moved} == {f"{owner['site']}-R01", f"{owner['site']}-R02"}


def test_drive_command_refuses_without_a_key_or_with_the_wrong_mode(
        fakerest, owner, monkeypatch, capsys):
    monkeypatch.delenv(sb.INGEST_KEY_ENV, raising=False)
    monkeypatch.setenv(sb.DEMO_TOKEN_ENV, "a" * 64)    # a demo token is not a key
    with sb.SandboxAPI(fakerest.base_url, ANON_KEY) as api:
        rc = sb.run_sandbox_drive(fakerest.base_url, ANON_KEY, owner["site"],
                                  ticks=1, interval=0.0, api=api,
                                  auth=sb.AUTH_INGEST)
        assert rc == sb.EXIT_ERROR
        assert "ingest key" in capsys.readouterr().err
        rc = sb.run_sandbox_drive(fakerest.base_url, ANON_KEY, owner["site"],
                                  ticks=1, interval=0.0, api=api, auth="nope")
        assert rc == sb.EXIT_ERROR


def test_spawn_driver_puts_the_key_in_env_and_the_mode_in_argv(fakerest, owner,
                                                               monkeypatch):
    seen: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, cmd, env=None, **kwargs):
            seen["cmd"], seen["env"], seen["kwargs"] = cmd, env, kwargs
            self.pid = 777

    monkeypatch.setattr(sb.subprocess, "Popen", _FakePopen)
    monkeypatch.setenv(sb.DEMO_TOKEN_ENV, "b" * 64)   # must not leak through
    sim = _start_sim(fakerest, owner)
    session = sb.DriverSession.from_rpc(sim)
    pid = sb._spawn_driver(base_url=fakerest.base_url, key=ANON_KEY,
                           session=session, robots=4, interval=1.0,
                           auth=sb.AUTH_INGEST)
    assert pid == 777
    cmd = seen["cmd"]
    assert "sandbox-drive" in cmd and owner["site"] in cmd
    assert cmd[cmd.index("--auth") + 1] == "ingest"
    assert sim["key"] not in cmd
    assert seen["env"][sb.INGEST_KEY_ENV] == sim["key"]
    assert sb.DEMO_TOKEN_ENV not in seen["env"]
    assert seen["kwargs"]["start_new_session"] is True


def test_registry_counts_the_two_kinds_separately(state_file):
    reg = sb.SandboxRegistry(state_file)
    later = sb._iso(datetime.now(timezone.utc) + timedelta(minutes=30))
    reg.add(sb.SandboxRecord(site_id="DEMO-000000000001", expires_at=later))
    reg.add(sb.SandboxRecord(site_id="WS-0badcafe", expires_at=later,
                             kind=sb.KIND_WORKSPACE))
    reg.add(sb.SandboxRecord(site_id="WS-0badcaff", expires_at=later,
                             kind=sb.KIND_WORKSPACE))
    assert reg.live_count() == 3
    assert reg.live_count(kind=sb.KIND_DEMO) == 1
    assert reg.live_count(kind=sb.KIND_WORKSPACE) == 2
    assert reg.find("WS-0badcafe").kind == sb.KIND_WORKSPACE
    # A pre-0019 registry file has no kind: it is a demo row.
    state_file.write_text(json.dumps({"sandboxes": [
        {"site_id": "DEMO-OLD", "expires_at": later, "kind": "garbage"},
        {"site_id": "DEMO-OLDER", "expires_at": later}]}))
    assert {r.kind for r in reg.load()} == {sb.KIND_DEMO}


def test_workspace_ceiling_is_configurable_by_env(monkeypatch):
    monkeypatch.delenv("YANTRAOPS_WORKSPACE_MAX", raising=False)
    assert sb.resolve_workspace_max_live() == sb.DEFAULT_WORKSPACE_MAX_LIVE == 12
    monkeypatch.setenv("YANTRAOPS_WORKSPACE_MAX", "3")
    assert sb.resolve_workspace_max_live() == 3
    assert sb.resolve_workspace_max_live(7) == 7
    monkeypatch.setenv("YANTRAOPS_WORKSPACE_MAX", "junk")
    assert sb.resolve_workspace_max_live() == 12


# ==========================================================================
# The door: /api/workspace/sim/{start,stop,status}
# ==========================================================================

class _SpawnSpy:
    """A spawn that never forks, recording what it was asked to start."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.next_pid = 5000

    def __call__(self, **kw) -> int:
        self.calls.append(kw)
        self.next_pid += 1
        return self.next_pid


def _door(fakerest, state_file, spy=None, **overrides):
    config = sh.ServeConfig(
        base_url=fakerest.base_url, key=ANON_KEY, console="https://x.test/c/",
        state_file=state_file, sim=spy is not None, history=False, robots=3,
        quiet=True, spawn=spy or sb._spawn_driver, **overrides)
    return sh.SandboxHTTP(config, host="127.0.0.1", port=0)


def _auth(jwt: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {jwt}"} if jwt else {}


def test_door_requires_a_jwt_on_every_workspace_route(fakerest, state_file):
    with _door(fakerest, state_file) as door:
        for method, route in (("POST", sh.ROUTE_WS_SIM_START),
                              ("POST", sh.ROUTE_WS_SIM_STOP),
                              ("GET", sh.ROUTE_WS_SIM_STATUS)):
            resp = httpx.request(method, f"{door.base_url}{route}", timeout=5.0)
            assert resp.status_code == 401, route
            assert resp.json()["reason"] == "unauthenticated"
            # Wrong scheme, empty bearer: same answer.
            resp = httpx.request(method, f"{door.base_url}{route}",
                                 headers={"Authorization": "Basic abc"}, timeout=5.0)
            assert resp.status_code == 401, route
        # A JWT PostgREST does not accept is 401 too (never 500, never 403).
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth("not-a-jwt"), timeout=5.0)
        assert resp.status_code == 401
        assert resp.json()["reason"] == "unauthenticated"
        assert door.service.registry.load() == []


def test_door_refuses_a_non_admin_with_403(fakerest, state_file, owner, operator):
    spy = _SpawnSpy()
    with _door(fakerest, state_file, spy) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(operator["jwt"]), timeout=5.0)
        assert resp.status_code == 403
        assert resp.json()["ok"] is False and resp.json()["reason"] == "forbidden"
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_STOP}",
                          headers=_auth(operator["jwt"]), timeout=5.0)
        assert resp.status_code == 403
        # status is operator+ and works; a role-less account is 403 too.
        resp = httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_STATUS}",
                         headers=_auth(operator["jwt"]), timeout=5.0)
        assert resp.status_code == 200 and resp.json()["running"] is False
        nobody = fakerest.mod.make_session_jwt(STRANGER)
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(nobody), timeout=5.0)
        assert resp.status_code == 403 and resp.json()["reason"] == "no_workspace"
    assert spy.calls == [] and fakerest.workspace_sims == {}


def test_door_starts_a_fleet_for_an_admin(fakerest, state_file, owner):
    spy = _SpawnSpy()
    site = owner["site"]
    with _door(fakerest, state_file, spy) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          json={"minutes": 30, "robots": 5},
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert set(body) == {"ok", "site_id", "expires_at", "robots"}
        assert body["ok"] is True and body["site_id"] == site and body["robots"] == 5
        assert "key" not in resp.text                 # the key never leaves the box
        # The RPC was called as the person (JWT forwarded, apikey anon).
        assert fakerest.workspace_sims[site]["robots"] == 5
        # Spawned with --auth ingest, the key in env, the key not in argv.
        assert len(spy.calls) == 1
        call = spy.calls[0]
        assert call["auth"] == sb.AUTH_INGEST and call["robots"] == 5
        assert call["key"] == ANON_KEY and call["base_url"] == fakerest.base_url
        session = call["session"]
        assert isinstance(session, sb.DriverSession) and session.site_id == site
        assert sb.valid_ingest_key(session.token)
        live_hash = next(k["key_hash"] for k in fakerest.ingest_keys.values()
                         if k["kind"] == "sim" and not k["revoked_at"])
        assert live_hash == fakerest.mod._ingest_key_hash(session.token)
        # Registry row: kind workspace, pid from the spawn, no token, no URL.
        records = door.service.registry.load()
        assert len(records) == 1
        rec = records[0]
        assert rec.site_id == site and rec.kind == sb.KIND_WORKSPACE
        assert rec.pid == 5001 and rec.console_url is None and rec.robots == 5
        assert session.token not in state_file.read_text()
        assert door.service.workspace_live_count() == 1
        assert door.service.live_count() == 0          # not a sandbox slot
        health = httpx.get(f"{door.base_url}{sh.ROUTE_HEALTH}", timeout=5.0).json()
        assert health["workspace_live"] == 1 and health["live"] == 0
        assert health["workspace_max_live"] == sb.DEFAULT_WORKSPACE_MAX_LIVE
        assert health["workspace_started"] == 1

        # Status reflects both the RPC and the registry.
        resp = httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_STATUS}",
                         headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 200
        status = resp.json()
        assert set(status) >= {"ok", "running", "expires_at", "robots", "driver_alive"}
        assert status["running"] is True and status["robots"] == 5
        assert status["driver_alive"] is False       # pid 5001 is nobody's

        # Starting again restarts: the old row is replaced, not duplicated.
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 201 and resp.json()["robots"] == 8
        assert len(door.service.registry.load()) == 1
        assert len(spy.calls) == 2

        # Stop: RPC stops it, the registry row is dropped.
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_STOP}",
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 200 and resp.json()["ok"] is True
        assert door.service.registry.load() == []
        assert fakerest.workspace_sims[site]["stopped_at"]
        resp = httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_STATUS}",
                         headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.json()["running"] is False and resp.json()["driver_alive"] is False


def test_door_clamps_the_body_and_ignores_junk(fakerest, state_file, owner):
    spy = _SpawnSpy()
    with _door(fakerest, state_file, spy) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          json={"minutes": 99999, "robots": -4, "site_id": "BLR-DC1"},
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 201
        assert resp.json()["robots"] == 2 and resp.json()["site_id"] == owner["site"]
        remaining = (sb._parse_ts(resp.json()["expires_at"])
                     - datetime.now(timezone.utc)).total_seconds()
        assert 1439 * 60 < remaining <= 1440 * 60
        # Not JSON at all: defaults.
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          content=b"<html>", headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 201 and resp.json()["robots"] == 8


def test_door_refuses_past_the_workspace_ceiling(fakerest, state_file, owner):
    spy = _SpawnSpy()
    later = sb._iso(datetime.now(timezone.utc) + timedelta(minutes=30))
    reg = sb.SandboxRegistry(state_file)
    reg.add(sb.SandboxRecord(site_id="WS-00000001", expires_at=later,
                             kind=sb.KIND_WORKSPACE))
    reg.add(sb.SandboxRecord(site_id="WS-00000002", expires_at=later,
                             kind=sb.KIND_WORKSPACE))
    # Demo sandboxes do not count against the workspace ceiling.
    for i in range(5):
        reg.add(sb.SandboxRecord(site_id=f"DEMO-00000000000{i}", expires_at=later))
    with _door(fakerest, state_file, spy, workspace_max_live=2, max_live=1) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 429
        body = resp.json()
        assert body["reason"] == "ceiling" and body["retry_after"]
        assert resp.headers["Retry-After"]
        assert spy.calls == [] and fakerest.workspace_sims == {}
        health = httpx.get(f"{door.base_url}{sh.ROUTE_HEALTH}", timeout=5.0).json()
        assert health["workspace_live"] == 2 and health["workspace_max_live"] == 2
        assert health["workspace_refused"] == 1
    # An expired workspace row frees its slot.
    past = sb._iso(datetime.now(timezone.utc) - timedelta(minutes=1))
    reg.add(sb.SandboxRecord(site_id="WS-00000002", expires_at=past,
                             kind=sb.KIND_WORKSPACE))
    with _door(fakerest, state_file, spy, workspace_max_live=2) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 201
        assert len(spy.calls) == 1


def test_door_rate_limits_sim_start_per_ip(fakerest, state_file, owner):
    spy = _SpawnSpy()
    with _door(fakerest, state_file, spy, workspace_rate=2,
               workspace_rate_window_s=3600.0) as door:
        codes = [httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                            headers=_auth(owner["jwt"]), timeout=5.0).status_code
                 for _ in range(3)]
        assert codes == [201, 201, 429]
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.json()["reason"] == "rate_limited" and resp.headers["Retry-After"]
        # Stop and status are not rate limited.
        assert httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_STATUS}",
                         headers=_auth(owner["jwt"]), timeout=5.0).status_code == 200
        assert httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_STOP}",
                          headers=_auth(owner["jwt"]), timeout=5.0).status_code == 200
    # The demo mint's quota is a separate counter.
    assert door.service.limiter.allow("127.0.0.1")


def test_door_answers_503_when_0019_is_not_applied(fakerest, state_file, owner):
    """PostgREST 404 PGRST202 ("could not find the function") is the one
    signal that the deployment never ran 0019 — the console hides the
    feature on a 503 not_enabled rather than showing an error."""
    fakerest.RPCS = {k: v for k, v in fakerest.RPCS.items()
                     if not k.startswith("workspace_")}
    spy = _SpawnSpy()
    with _door(fakerest, state_file, spy) as door:
        for method, route in (("POST", sh.ROUTE_WS_SIM_START),
                              ("POST", sh.ROUTE_WS_SIM_STOP),
                              ("GET", sh.ROUTE_WS_SIM_STATUS)):
            resp = httpx.request(method, f"{door.base_url}{route}",
                                 headers=_auth(owner["jwt"]), timeout=5.0)
            assert resp.status_code == 503, route
            assert resp.json()["reason"] == "not_enabled"
            assert resp.headers["Retry-After"]
    assert spy.calls == [] and door.service.registry.load() == []


def test_door_survives_a_backend_that_is_down(state_file, owner):
    config = sh.ServeConfig(base_url="http://127.0.0.1:9", key=ANON_KEY,
                            state_file=state_file, sim=False, quiet=True)
    with sh.SandboxHTTP(config, host="127.0.0.1", port=0) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(owner["jwt"]), timeout=10.0)
        assert resp.status_code == 502 and resp.json()["reason"] == "error"
        assert httpx.get(f"{door.base_url}{sh.ROUTE_HEALTH}",
                         timeout=5.0).json()["workspace_live"] == 0


def test_door_ends_the_run_when_the_driver_will_not_start(fakerest, state_file, owner):
    def boom(**kw):
        raise OSError("fork: resource temporarily unavailable")

    with _door(fakerest, state_file, boom) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          headers=_auth(owner["jwt"]), timeout=5.0)
        assert resp.status_code == 502 and resp.json()["reason"] == "error"
        assert "fork" in resp.json()["detail"]
        assert door.service.registry.load() == []
    # The RPC-side run was stopped too: no live key is left dangling.
    assert fakerest.workspace_sims[owner["site"]]["stopped_at"]
    assert not [k for k in fakerest.ingest_keys.values() if not k["revoked_at"]]


def test_door_rejects_the_wrong_method_and_preflights_authorization(
        fakerest, state_file):
    with _door(fakerest, state_file) as door:
        assert httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                         timeout=5.0).status_code == 405
        assert httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_STOP}",
                         timeout=5.0).status_code == 405
        assert httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_STATUS}",
                          timeout=5.0).status_code == 404
        pre = httpx.request("OPTIONS", f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                            headers={"Origin": "https://x.test"}, timeout=5.0)
        assert pre.status_code == 204
        assert "authorization" in pre.headers["Access-Control-Allow-Headers"].lower()


def test_door_end_to_end_with_a_real_driver(fakerest, state_file, owner):
    """The whole path: start -> a real child process moves the workspace
    fleet with its ingest key -> stop kills it and revokes the key."""
    site = owner["site"]
    config = sh.ServeConfig(base_url=fakerest.base_url, key=ANON_KEY,
                            state_file=state_file, sim=True, history=False,
                            interval=0.2, quiet=True)
    with sh.SandboxHTTP(config, host="127.0.0.1", port=0) as door:
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_START}",
                          json={"robots": 2}, headers=_auth(owner["jwt"]),
                          timeout=20.0)
        assert resp.status_code == 201, resp.text
        rec = door.service.registry.load()[0]
        assert rec.pid and rec.kind == sb.KIND_WORKSPACE
        moved = False
        for _ in range(100):
            rows = [r for r in fakerest.tables["robots"] if r["site_id"] == site]
            if len(rows) == 2 and any(r.get("updated_at") for r in rows):
                moved = True
                break
            import time
            time.sleep(0.1)
        assert moved, "the spawned driver never wrote the workspace fleet"
        assert {r["id"] for r in rows} == {f"{site}-R01", f"{site}-R02"}
        status = httpx.get(f"{door.base_url}{sh.ROUTE_WS_SIM_STATUS}",
                           headers=_auth(owner["jwt"]), timeout=5.0).json()
        assert status["running"] is True and status["driver_alive"] is True
        resp = httpx.post(f"{door.base_url}{sh.ROUTE_WS_SIM_STOP}",
                          headers=_auth(owner["jwt"]), timeout=10.0)
        assert resp.status_code == 200
        assert not sb._pid_alive(rec.pid)
        assert door.service.registry.load() == []
    # Nothing escaped the workspace.
    assert [r["id"] for r in fakerest.tables["robots"] if r["site_id"] == "BLR-DC1"] == ["AMR-01"]
    assert fakerest.tables["fleet_meta"] == [{"id": 1, "writer_id": "real", "sim_min": 3}]


# ==========================================================================
# CLI
# ==========================================================================

def test_cli_parses_the_workspace_flags():
    parser = build_parser()
    args = parser.parse_args(["sandbox-drive", "--site", "WS-0badcafe",
                              "--auth", "ingest", "--ticks", "2"])
    assert args.auth == "ingest" and args.site == "WS-0badcafe"
    args = parser.parse_args(["sandbox-drive", "--site", "DEMO-01"])
    assert args.auth == "demo"
    with pytest.raises(SystemExit):
        parser.parse_args(["sandbox-drive", "--site", "WS-x", "--auth", "service"])
    args = parser.parse_args(["sandbox-serve", "--workspace-max-live", "3",
                              "--workspace-rate", "4",
                              "--workspace-rate-window", "60"])
    assert args.workspace_max_live == 3 and args.workspace_rate == 4
    assert args.workspace_rate_window == 60.0
    assert parser.parse_args(["sandbox-serve"]).workspace_max_live is None


def test_cli_dispatches_sandbox_drive_in_ingest_mode(fakerest, owner, monkeypatch):
    from yantraops.__main__ import main
    sim = _start_sim(fakerest, owner, robots=2)
    monkeypatch.setenv(sb.INGEST_KEY_ENV, sim["key"])
    rc = main(["sandbox-drive", "--url", fakerest.base_url, "--key", ANON_KEY,
               "--site", owner["site"], "--auth", "ingest", "--robots", "2",
               "--interval", "0", "--ticks", "2"])
    assert rc == sb.EXIT_OK
    assert len([r for r in fakerest.tables["robots"]
                if r["site_id"] == owner["site"]]) == 2
