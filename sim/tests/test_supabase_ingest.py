"""Workspace (ingest-key) mode of the Supabase transport — supabase/0019,
docs/WORKSPACES.md. Fully offline via httpx.MockTransport.

With a key configured the simulator is a self-serve workspace's own robot
connector: every request carries ``x-yf-ingest-key``, every id is
namespaced ``<site>-``, every row is stamped with the workspace's site,
and ``fleet_meta`` — which a key cannot reach — is never written. Without
a key nothing changes, which the existing transport tests already pin.
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from yantrasim.__main__ import main
from yantrasim.sim import FleetSim, SCRIPTED_FAULT_TICK
from yantrasim.transports.supabase import (
    INGEST_KEY_HEADER, SupabaseTransport, check_ingest_config, namespace_rows,
    resolve_ingest_key, strip_namespace,
)

from conftest import FIXED_NOW

KEY = "yk_" + "ab" * 32
SITE = "WS-0badcafe"


@pytest.fixture()
def recorder():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(201)

    return requests, httpx.Client(transport=httpx.MockTransport(handler))


def _by_table(requests):
    out = {}
    for req in requests:
        table = req.url.path.rsplit("/", 1)[-1]
        body = json.loads(req.content) if req.content else None
        out.setdefault(table, []).append((req, body))
    return out


def _fault_tick(seed: int = 8):
    fleet = FleetSim(seed=seed)
    out = None
    while fleet.tick_count < SCRIPTED_FAULT_TICK:
        out = fleet.tick(dt_s=10.0, now=FIXED_NOW)
    return fleet, out


def test_key_sends_the_header_namespaces_ids_and_skips_fleet_meta(recorder, caplog):
    requests, client = recorder
    fleet, out = _fault_tick()
    t = SupabaseTransport(client=client, site=SITE, ingest_key=KEY, history_every=1)
    with caplog.at_level(logging.INFO, logger="yantrasim.transports.supabase"):
        t.publish(out)
        t.publish(fleet.tick(dt_s=10.0, now=FIXED_NOW))

    by_table = _by_table(requests)
    assert "fleet_meta" not in by_table, "a key cannot write fleet_meta"
    assert {"robots", "alerts", "missions", "robot_telemetry"} <= set(by_table)
    for req in requests:
        assert req.headers[INGEST_KEY_HEADER] == KEY
        assert req.headers["apikey"] and req.headers["Authorization"].startswith("Bearer ")
    _req, robots = by_table["robots"][0]
    assert {r["id"] for r in robots} == {f"{SITE}-AMR-{i:02d}" for i in range(1, 11)}
    assert all(r["site_id"] == SITE for r in robots)
    _req, alerts = by_table["alerts"][0]
    assert alerts and all(a["id"].startswith(f"{SITE}-al-") for a in alerts)
    assert all(a["src"].startswith(f"{SITE}-AMR-") for a in alerts)
    assert all(a["site_id"] == SITE for a in alerts)
    _req, missions = by_table["missions"][0]
    assert all(m["id"].startswith(f"{SITE}-") for m in missions)
    assert all(x.startswith(f"{SITE}-AMR-") for m in missions for x in m["robots"])
    _req, samples = by_table["robot_telemetry"][0]
    assert all(s["robot_id"].startswith(f"{SITE}-AMR-") for s in samples)
    assert all(s["site_id"] == SITE for s in samples)
    # The skip is said once, at INFO, not once per tick.
    skips = [r for r in caplog.records if "fleet_meta heartbeat skipped" in r.getMessage()]
    assert len(skips) == 1 and skips[0].levelno == logging.INFO


def test_without_a_key_nothing_changes(recorder):
    requests, client = recorder
    fleet = FleetSim(seed=7)
    t = SupabaseTransport(client=client, writer_id=fleet.writer_id)
    assert t.ingest_key is None
    t.publish(fleet.tick(dt_s=10.0, now=FIXED_NOW))
    by_table = _by_table(requests)
    assert "fleet_meta" in by_table
    assert all(INGEST_KEY_HEADER not in req.headers for req in requests)
    assert {r["id"] for r in by_table["robots"][0][1]} == {
        f"AMR-{i:02d}" for i in range(1, 11)}


def test_key_requires_a_workspace_site(recorder):
    _requests, client = recorder
    for bad_site in (None, "BLR-DC1", "DEMO-ABCDEF012345", "WS-nothex!", "ws-0badcafe"):
        with pytest.raises(ValueError, match="self-serve workspace"):
            SupabaseTransport(client=client, site=bad_site, ingest_key=KEY)
    for bad_key in ("yk_short", KEY.upper(), "zz_" + "ab" * 32, KEY + "0"):
        with pytest.raises(ValueError, match="malformed"):
            SupabaseTransport(client=client, site=SITE, ingest_key=bad_key)
    # The guard is a no-op without a key: legacy sites are fine.
    check_ingest_config(None, "BLR-DC1")


def test_key_and_site_come_from_the_environment(recorder, monkeypatch):
    requests, client = recorder
    monkeypatch.setenv("YANTRA_INGEST_KEY", KEY)
    monkeypatch.setenv("YANTRA_SITE_ID", SITE)
    assert resolve_ingest_key() == KEY
    t = SupabaseTransport(client=client)
    assert t.ingest_key == KEY and t.site == SITE
    t.publish(FleetSim(seed=7).tick(dt_s=10.0, now=FIXED_NOW))
    assert all(req.headers[INGEST_KEY_HEADER] == KEY for req in requests)
    # An explicit argument beats the environment.
    monkeypatch.setenv("YANTRA_INGEST_KEY", "yk_" + "ff" * 32)
    assert SupabaseTransport(client=client, site=SITE, ingest_key=KEY).ingest_key == KEY
    monkeypatch.setenv("YANTRA_INGEST_KEY", "   ")
    assert resolve_ingest_key() is None


def test_namespace_rows_is_idempotent_and_leaves_fleet_labels_alone():
    rows = namespace_rows("alerts", [
        {"id": "al-1", "src": "AMR-01", "site_id": "BLR-DC1"},
        {"id": f"{SITE}-al-2", "src": "fleet", "site_id": SITE},
        {"id": "al-3", "src": None},
    ], SITE)
    assert [r["id"] for r in rows] == [f"{SITE}-al-1", f"{SITE}-al-2", f"{SITE}-al-3"]
    assert [r["src"] for r in rows] == [f"{SITE}-AMR-01", "fleet", None]
    assert all(r["site_id"] == SITE for r in rows)
    assert strip_namespace(f"{SITE}-AMR-01", SITE) == "AMR-01"
    assert strip_namespace("AMR-01", SITE) == "AMR-01"


def test_poll_commands_filters_by_site_and_strips_the_prefix():
    seen: list[httpx.Request] = []
    applied: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=[
                {"id": "c1", "robot_id": f"{SITE}-AMR-03", "cmd": "pause",
                 "site_id": SITE}])
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    t = SupabaseTransport(client=client, site=SITE, ingest_key=KEY)
    n = t.poll_commands(lambda rid, cmd: (applied.append((rid, cmd)) or True, "ok"))
    assert n == 1 and applied == [("AMR-03", "pause")]
    poll = seen[0]
    assert poll.url.params["site_id"] == f"eq.{SITE}"
    assert poll.headers[INGEST_KEY_HEADER] == KEY
    ack = seen[1]
    assert ack.method == "PATCH" and ack.headers[INGEST_KEY_HEADER] == KEY
    assert json.loads(ack.content)["status"] == "executed"


def test_cli_runs_in_workspace_mode_without_polling_app_config(monkeypatch):
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert request.headers[INGEST_KEY_HEADER] == KEY
        return httpx.Response(200, json=[]) if request.method == "GET" else httpx.Response(201)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setenv("YANTRA_INGEST_KEY", KEY)
    rc = main(["--supabase", "--ticks", "2", "--interval", "0",
               "--url", "https://x.test", "--key", "k", "--site", SITE],
              client=client)
    assert rc == 0
    assert not any(p.endswith("/app_config") for p in paths)
    assert not any(p.endswith("/fleet_meta") for p in paths)
    assert any(p.endswith("/robots") for p in paths)


def test_cli_refuses_a_key_without_a_workspace_site(monkeypatch, capsys):
    monkeypatch.delenv("YANTRA_SITE_ID", raising=False)
    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(201)))
    rc = main(["--supabase", "--ticks", "1", "--interval", "0",
               "--url", "https://x.test", "--key", "k", "--ingest-key", KEY],
              client=client)
    assert rc == 2
    assert "WS-<8 hex>" in capsys.readouterr().err
    rc = main(["--supabase", "--ticks", "1", "--interval", "0",
               "--url", "https://x.test", "--key", "k", "--site", SITE,
               "--ingest-key", "nope"], client=client)
    assert rc == 2
