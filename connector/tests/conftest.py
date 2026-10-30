"""Shared offline fixtures."""
import pytest


@pytest.fixture(autouse=True)
def _test_backend(monkeypatch):
    """Components fail closed without SUPABASE_URL/KEY (yantracore.backend);
    give every test an unroutable placeholder so nothing can reach a real one."""
    monkeypatch.setenv("SUPABASE_URL", "https://backend.invalid")
    monkeypatch.setenv("SUPABASE_KEY", "test-key")
    monkeypatch.delenv("YANTRA_ALLOW_DEMO_BACKEND", raising=False)
