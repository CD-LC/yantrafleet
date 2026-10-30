"""POST /ask is throttled per client; X-Forwarded-For is only believed when
the operator says how many reverse proxies to trust.

Why it matters: /ask is open unless SARATHI_TOKEN is set, and with an LLM key
configured every answer can cost money - an unthrottled endpoint is a free way
to spend the operator's quota.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sarathi.app import RateLimiter, create_app
from sarathi.config import Settings
from sarathi.transport import StaticTransport

Q = {"question": "Which robots are low on battery?"}


def _client(transport: StaticTransport, monkeypatch, per_min="3", hops="0"):
    monkeypatch.setenv("SARATHI_RATE_PER_MIN", per_min)
    monkeypatch.setenv("SARATHI_TRUSTED_PROXY_HOPS", hops)
    monkeypatch.delenv("SARATHI_TOKEN", raising=False)
    s = Settings(supabase_url="https://x.invalid", supabase_key="k", model=None)
    return TestClient(create_app(transport=transport, settings=s))


def test_limit_then_429_with_retry_after(transport, monkeypatch):
    c = _client(transport, monkeypatch, per_min="3")
    assert [c.post("/ask", json=Q).status_code for _ in range(3)] == [200, 200, 200]
    r = c.post("/ask", json=Q)
    assert r.status_code == 429
    assert r.json()["error"] == "rate_limited"
    assert int(r.headers["retry-after"]) >= 1


def test_limit_is_checked_before_auth_so_floods_stay_cheap(transport, monkeypatch):
    c = _client(transport, monkeypatch, per_min="1")
    monkeypatch.setenv("SARATHI_TOKEN", "t")
    c.post("/ask", json=Q)
    assert c.post("/ask", json=Q).status_code == 429


def test_zero_disables_the_limit(transport, monkeypatch):
    c = _client(transport, monkeypatch, per_min="0")
    assert all(c.post("/ask", json=Q).status_code == 200 for _ in range(10))


def test_forged_xff_cannot_buy_a_fresh_quota_by_default(transport, monkeypatch):
    c = _client(transport, monkeypatch, per_min="2", hops="0")
    codes = [c.post("/ask", json=Q, headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code
             for i in range(4)]
    assert codes == [200, 200, 429, 429]


def test_trusted_hop_charges_the_real_client_not_the_proxy(transport, monkeypatch):
    c = _client(transport, monkeypatch, per_min="1", hops="1")
    # nginx appends the address it saw as the LAST entry; anything before it is
    # client-supplied and must not matter.
    a = {"X-Forwarded-For": "1.1.1.1, 10.0.0.5"}
    b = {"X-Forwarded-For": "1.1.1.1, 10.0.0.6"}
    assert c.post("/ask", json=Q, headers=a).status_code == 200
    assert c.post("/ask", json=Q, headers=a).status_code == 429
    assert c.post("/ask", json=Q, headers=b).status_code == 200   # different real client


def test_limiter_window_slides_and_table_is_bounded():
    t = [0.0]
    rl = RateLimiter(2, window_s=60, clock=lambda: t[0])
    assert rl.check("k") is None and rl.check("k") is None
    assert rl.check("k") == pytest.approx(60.0)
    t[0] = 61.0
    assert rl.check("k") is None
    from sarathi import app as appmod
    appmod.RATE_TABLE_MAX, old = 50, appmod.RATE_TABLE_MAX
    try:
        for i in range(500):
            rl.check(f"ip{i}")
        assert len(rl._hits) <= 50
    finally:
        appmod.RATE_TABLE_MAX = old


def test_cors_can_be_pinned_to_named_origins(transport, monkeypatch):
    monkeypatch.setenv("SARATHI_CORS_ORIGINS", "https://fleet.example")
    c = _client(transport, monkeypatch, per_min="0")
    ok = c.options("/ask", headers={"Origin": "https://fleet.example",
                                    "Access-Control-Request-Method": "POST"})
    bad = c.options("/ask", headers={"Origin": "https://evil.example",
                                     "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "https://fleet.example"
    assert "access-control-allow-origin" not in bad.headers
