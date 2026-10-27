"""Per-request site scope + credential forwarding (docs/WORKSPACES.md s.6).

StaticTransport pattern: a recording subclass notes every query's params
and the per-request headers in effect at that moment, so the tests assert
exactly what PostgREST would have been sent - the site filter on every
table, and the asker's own credential (never anyone else's).
"""
from __future__ import annotations

import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from sarathi.app import create_app
from sarathi.config import Settings
from sarathi.scope import current_headers, current_site, request_scope
from sarathi.tools import Toolbox
from sarathi.transport import StaticTransport, SupabaseTransport

SITE = "WS-0badcafe"
JWT = "aaa.bbb.ccc"
DEMO = "ab" * 32


class RecordingTransport(StaticTransport):
    """StaticTransport that remembers (table, params, headers) per call and
    drops site-filtered rows the way PostgREST would."""

    def __init__(self, tables):
        super().__init__(tables)
        self.calls: list[tuple[str, list, dict]] = []

    def get(self, table, params):
        self.calls.append((table, list(params), current_headers()))
        return super().get(table, params)


def _settings() -> Settings:
    return Settings(supabase_url="https://x.invalid", supabase_key="k", model=None)


@pytest.fixture()
def tables(transport):
    t = {k: [dict(r) for r in v] for k, v in transport._tables.items()}
    for name in ("robots", "alerts", "incidents", "commands", "robot_telemetry"):
        for i, row in enumerate(t[name]):
            row["site_id"] = SITE if i % 2 == 0 else "BLR-DC1"
    return t


def test_toolbox_filters_every_table_query_by_site(tables):
    rec = RecordingTransport(tables)
    box = Toolbox(transport=rec, site=SITE)
    box.get_fleet_summary()
    box.query_robots(status="active")
    box.query_alerts(ack=False)
    box.query_incidents()
    box.query_commands()
    box.query_telemetry(robot_id="R-004")
    queried = {t for t, _p, _h in rec.calls}
    assert queried == {"robots", "alerts", "incidents", "commands",
                       "robot_telemetry"}
    for table, params, _h in rec.calls:
        assert ("site_id", f"eq.{SITE}") in params, table
    # fleet_meta has no site_id: it is skipped in a scoped request, so the
    # global heartbeat is never read (and never mistaken for this site's).
    assert "fleet_meta" not in queried
    summary = box.log[0].data
    assert summary["throughput"] is None and summary["sim_min"] is None
    assert summary["robots_total"] == 3        # only the WS rows of 6


def test_unscoped_toolbox_is_unchanged(tables):
    rec = RecordingTransport(tables)
    box = Toolbox(transport=rec)
    box.get_fleet_summary()
    assert all(("site_id", f"eq.{SITE}") not in p for _t, p, _h in rec.calls)
    assert "fleet_meta" in {t for t, _p, _h in rec.calls}


def test_ask_site_and_headers_reach_the_transport(tables):
    rec = RecordingTransport(tables)
    client = TestClient(create_app(transport=rec, settings=_settings()))
    resp = client.post(
        "/ask", json={"question": "Which robots are low on battery?",
                      "site": SITE},
        headers={"X-YF-User-Token": JWT, "X-YF-Demo-Token": DEMO})
    assert resp.status_code == 200
    assert rec.calls, "the question must have read data"
    for table, params, headers in rec.calls:
        assert ("site_id", f"eq.{SITE}") in params, table
        assert headers == {"Authorization": f"Bearer {JWT}",
                           "x-yf-demo-token": DEMO}
    # Scope never leaks past the request that set it.
    assert current_site() is None and current_headers() == {}


def test_ask_without_site_or_headers_behaves_as_before(tables):
    rec = RecordingTransport(tables)
    client = TestClient(create_app(transport=rec, settings=_settings()))
    assert client.post("/ask", json={"question": "fleet status"}).status_code == 200
    for _t, params, headers in rec.calls:
        assert not any(k == "site_id" for k, _v in params)
        assert headers == {}


def test_bad_site_is_rejected_and_junk_credentials_are_dropped(tables):
    rec = RecordingTransport(tables)
    client = TestClient(create_app(transport=rec, settings=_settings()))
    for bad in ("x&y=1", "a b", "eq.x,or(a.eq.b)", "A" * 65, ""):
        resp = client.post("/ask", json={"question": "status", "site": bad})
        assert resp.status_code == 422, bad
    assert rec.calls == []
    client.post("/ask", json={"question": "status", "site": SITE},
                headers={"X-YF-User-Token": "not a jwt!", "X-YF-Demo-Token": "XYZ"})
    assert rec.calls and all(h == {} for _t, _p, h in rec.calls)
    # "Bearer " prefixes are tolerated.
    client.post("/ask", json={"question": "status"},
                headers={"X-YF-User-Token": f"Bearer {JWT}"})
    assert rec.calls[-1][2] == {"Authorization": f"Bearer {JWT}"}


def test_concurrent_requests_never_share_credentials(tables):
    """Two askers in flight at once each see only their own token."""
    seen: dict[str, set[str]] = {"a": set(), "b": set()}
    barrier = threading.Barrier(2)

    class Slow(RecordingTransport):
        def get(self, table, params):
            barrier.wait(timeout=5)          # both requests are mid-query
            who = current_headers().get("Authorization", "")
            seen[who[-1]].add(who)
            return super().get(table, params)

    app = create_app(transport=Slow(tables), settings=_settings())
    results = {}

    def go(tag: str) -> None:
        with TestClient(app) as c:
            results[tag] = c.post(
                "/ask", json={"question": "fleet status", "site": SITE},
                headers={"X-YF-User-Token": f"tok.{tag}.{tag}"}).status_code

    threads = [threading.Thread(target=go, args=(t,)) for t in "ab"]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert results == {"a": 200, "b": 200}
    assert seen["a"] == {"Bearer tok.a.a"} and seen["b"] == {"Bearer tok.b.b"}


def test_supabase_transport_sends_per_request_headers_only():
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=[])

    client = httpx.Client(base_url="https://x.test/rest/v1",
                          headers={"apikey": "anon", "Authorization": "Bearer anon"},
                          transport=httpx.MockTransport(handler))
    t = SupabaseTransport("https://x.test", "anon", client=client)
    with request_scope(SITE, JWT, DEMO):
        t.get("robots", [("site_id", f"eq.{SITE}")])
    t.get("robots", [])
    scoped, plain = sent
    assert scoped.headers["apikey"] == "anon"                    # still anon
    assert scoped.headers["authorization"] == f"Bearer {JWT}"    # asker's JWT
    assert scoped.headers["x-yf-demo-token"] == DEMO
    assert plain.headers["authorization"] == "Bearer anon"       # no bleed
    assert "x-yf-demo-token" not in plain.headers
