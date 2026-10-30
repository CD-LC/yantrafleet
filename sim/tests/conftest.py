"""Shared fixtures. All tests are OFFLINE: HTTP is httpx.MockTransport,
MQTT is a recording fake — supabase.co / brokers are never contacted."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # sim/ on path

from yantracore.site import stop_site_sync  # noqa: E402
from yantrasim.sim import FleetSim  # noqa: E402

FIXED_NOW = datetime(2026, 8, 26, 10, 15, 32, 512000, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clean_site_sync():
    """yantrasim.__main__.main() starts a live YANTRA_SITE_ID sync
    (yantracore.site.start_site_sync) in --supabase mode; without this,
    the first test to run main() would leave its SiteSync active (and
    its fake client polling in a background thread) for every later
    test in this session — see core/yantracore/site.py's module
    docstring."""
    stop_site_sync()
    yield
    stop_site_sync()


@pytest.fixture()
def sim() -> FleetSim:
    return FleetSim(seed=7)


@pytest.fixture()
def one_tick(sim: FleetSim):
    return sim.tick(dt_s=10.0, now=FIXED_NOW)


@pytest.fixture(autouse=True)
def _test_backend(monkeypatch):
    """Components fail closed without SUPABASE_URL/KEY (yantracore.backend);
    give every test an unroutable placeholder so nothing can reach a real one."""
    monkeypatch.setenv("SUPABASE_URL", "https://backend.invalid")
    monkeypatch.setenv("SUPABASE_KEY", "test-key")
    monkeypatch.delenv("YANTRA_ALLOW_DEMO_BACKEND", raising=False)
