"""Workspace (ingest-key) mode of the connector - supabase/0019,
docs/WORKSPACES.md. Offline via httpx.MockTransport.

With a key the bridge is a self-serve workspace's own connector: every
request carries ``x-yf-ingest-key``, every robot/alert/telemetry id is
prefixed ``<site>-``, rows are stamped with the workspace site, and the
``fleet_meta`` heartbeat - which a key cannot reach - is skipped (logged
once at INFO). A key without a WS-<8 hex> site, or a malformed key, is
refused at startup, before any request is made.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
import pytest

from yantrabridge.__main__ import main
from yantrabridge.commands import CommandPublisher
from yantrabridge.sink import (INGEST_KEY_HEADER, SupabaseSink,
                               namespace_rows, strip_namespace)

SAMPLE = Path(__file__).resolve().parent.parent / "sample.jsonl"
KEY = "yk_" + "cd" * 32
SITE = "WS-0badcafe"


class Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json=[]) if request.method == "GET" else httpx.Response(201)

    def body(self, table: str):
        return [json.loads(r.content) for r in self.requests
                if r.url.path.endswith("/" + table)]


def make_sink(rec: Recorder, **kw) -> SupabaseSink:
    return SupabaseSink("https://example.supabase.co", "anon",
                        transport=httpx.MockTransport(rec.handler), **kw)


def test_sink_sends_header_namespaces_and_skips_heartbeat(caplog):
    rec = Recorder()
    robots = [{"id": "AGV-001", "vendor": "yantra", "site_id": "BLR-DC1"}]
    alerts = [{"id": "al-agv-001-x", "src": "AGV-001", "site_id": "BLR-DC1"}]
    telemetry = [{"robot_id": "AGV-001", "ts": "t", "site_id": "BLR-DC1"}]
    with caplog.at_level(logging.INFO, logger="yantrabridge.sink"):
        with make_sink(rec, ingest_key=KEY, site=SITE) as sink:
            counts = sink.push(robots, alerts)
            sink.insert_telemetry(telemetry)
            sink.heartbeat()
    assert counts == {"robots": 1, "alerts": 1}
    assert all(r.headers[INGEST_KEY_HEADER] == KEY for r in rec.requests)
    assert not any(r.url.path.endswith("/fleet_meta") for r in rec.requests)
    assert rec.body("robots")[0][0]["id"] == f"{SITE}-AGV-001"
    assert rec.body("robots")[0][0]["site_id"] == SITE
    a = rec.body("alerts")[0][0]
    assert a["id"] == f"{SITE}-al-agv-001-x" and a["src"] == f"{SITE}-AGV-001"
    t = rec.body("robot_telemetry")[0][0]
    assert t["robot_id"] == f"{SITE}-AGV-001" and t["site_id"] == SITE
    skips = [r for r in caplog.records if "heartbeat skipped" in r.getMessage()]
    assert len(skips) == 1 and skips[0].levelno == logging.INFO


def test_sink_without_a_key_is_unchanged():
    rec = Recorder()
    with make_sink(rec) as sink:
        sink.push([{"id": "AGV-001"}], [])
    assert all(INGEST_KEY_HEADER not in r.headers for r in rec.requests)
    assert rec.body("robots")[0][0]["id"] == "AGV-001"
    assert any(r.url.path.endswith("/fleet_meta") for r in rec.requests)


def test_sink_refuses_a_key_without_a_workspace_site(monkeypatch):
    monkeypatch.delenv("YANTRA_SITE_ID", raising=False)
    rec = Recorder()
    for site in (None, "BLR-DC1", "DEMO-ABCDEF012345", "WS-XYZ"):
        with pytest.raises(ValueError, match="self-serve workspace"):
            make_sink(rec, ingest_key=KEY, site=site)
    with pytest.raises(ValueError, match="malformed"):
        make_sink(rec, ingest_key="yk_nope", site=SITE)
    assert rec.requests == []


def test_env_supplies_key_and_site(monkeypatch):
    monkeypatch.setenv("YANTRA_INGEST_KEY", KEY)
    monkeypatch.setenv("YANTRA_SITE_ID", SITE)
    rec = Recorder()
    with make_sink(rec) as sink:
        sink.upsert_robots([{"id": "AGV-9"}])
    assert rec.requests[0].headers[INGEST_KEY_HEADER] == KEY
    assert rec.body("robots")[0][0]["id"] == f"{SITE}-AGV-9"


def test_namespace_helpers_are_idempotent():
    rows = namespace_rows("robots", [{"id": f"{SITE}-A"}, {"id": "B"}], SITE)
    assert [r["id"] for r in rows] == [f"{SITE}-A", f"{SITE}-B"]
    assert strip_namespace(f"{SITE}-B", SITE) == "B"


def test_command_publisher_uses_the_key_and_strips_the_prefix():
    seen: list[httpx.Request] = []
    published: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/commands") and request.method == "GET":
            return httpx.Response(200, json=[
                {"id": "c1", "robot_id": f"{SITE}-AGV-001", "cmd": "pause",
                 "site_id": SITE}])
        if request.url.path.endswith("/robots"):
            return httpx.Response(200, json=[{"id": f"{SITE}-AGV-001", "vendor": "yantra"}])
        return httpx.Response(204)

    pub = CommandPublisher(lambda t, p, qos=0: published.append((t, p)),
                           "https://x.test", "anon", site=SITE, ingest_key=KEY,
                           transport=httpx.MockTransport(handler))
    assert pub.poll() == 1
    topic, payload = published[0]
    assert topic == "uagv/v2/yantra/AGV_001/instantActions"
    lookup = next(r for r in seen if r.url.path.endswith("/robots"))
    assert lookup.url.params["id"] == f"eq.{SITE}-AGV_001"
    assert lookup.url.params["site_id"] == f"eq.{SITE}"
    assert all(r.headers[INGEST_KEY_HEADER] == KEY for r in seen)


class TestCli:
    def test_file_mode_refuses_a_key_without_a_workspace_site(self, monkeypatch, capsys):
        monkeypatch.delenv("YANTRA_SITE_ID", raising=False)
        rc = main(["--file", str(SAMPLE), "--ingest-key", KEY])
        assert rc == 2
        assert "WS-<8 hex>" in capsys.readouterr().err
        rc = main(["--file", str(SAMPLE), "--site", SITE, "--ingest-key", "bad"])
        assert rc == 2

    def test_file_mode_pushes_namespaced_rows(self, monkeypatch, capsys):
        rec = Recorder()
        real = httpx.Client

        def patched(*a, **kw):
            kw["transport"] = httpx.MockTransport(rec.handler)
            return real(*a, **kw)

        monkeypatch.setattr("yantrabridge.sink.httpx.Client", patched)
        monkeypatch.setenv("YANTRA_INGEST_KEY", KEY)
        rc = main(["--file", str(SAMPLE), "--site", SITE,
                   "--supabase-url", "https://x.test", "--supabase-key", "anon"])
        assert rc == 0
        assert "heartbeat skipped" in capsys.readouterr().out
        ids = {r["id"] for batch in rec.body("robots") for r in batch}
        assert ids == {f"{SITE}-AGV-00{i}" for i in (1, 2, 3)}
        assert not any(r.url.path.endswith("/fleet_meta") for r in rec.requests)
        assert all(r.headers[INGEST_KEY_HEADER] == KEY for r in rec.requests)

    def test_import_subcommand_validates_too(self, monkeypatch, capsys):
        monkeypatch.delenv("YANTRA_SITE_ID", raising=False)
        rc = main(["import", "--jsonl", str(SAMPLE), "--ingest-key", KEY])
        assert rc == 2
        assert "WS-<8 hex>" in capsys.readouterr().err

    def test_import_subcommand_writes_namespaced_rows(self, monkeypatch):
        rec = Recorder()
        real = httpx.Client

        def patched(*a, **kw):
            kw["transport"] = httpx.MockTransport(rec.handler)
            return real(*a, **kw)

        monkeypatch.setattr("yantrabridge.sink.httpx.Client", patched)
        rc = main(["import", "--jsonl", str(SAMPLE), "--site", SITE,
                   "--ingest-key", KEY, "--supabase-url", "https://x.test",
                   "--supabase-key", "anon"])
        assert rc == 0
        ids = {r["id"] for batch in rec.body("robots") for r in batch}
        assert ids and all(i.startswith(f"{SITE}-") for i in ids)
        tel = [r for batch in rec.body("robot_telemetry") for r in batch]
        assert tel and all(r["robot_id"].startswith(f"{SITE}-") for r in tel)
        assert not any(r.url.path.endswith("/fleet_meta") for r in rec.requests)
