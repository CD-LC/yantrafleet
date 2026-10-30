"""Optional bearer auth on POST /ask, driven by env SARATHI_TOKEN.

Unset: closed by default (401 ``auth_not_configured``) unless the operator
sets SARATHI_ALLOW_OPEN=1 (what every other test runs under). Set: /ask requires the exact
``Authorization: Bearer <token>`` header and answers 401 JSON otherwise;
/health stays open but reports ``auth_required``.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sarathi.app import create_app
from sarathi.config import Settings
from sarathi.transport import StaticTransport

TOKEN = "s3cret-fleet-token"
QUESTION = {"question": "Which robots are low on battery?"}


def _settings() -> Settings:
    return Settings(supabase_url="https://x.invalid", supabase_key="k", model=None)


def _client(transport: StaticTransport) -> TestClient:
    return TestClient(create_app(transport=transport, settings=_settings()))


# -- SARATHI_TOKEN unset ------------------------------------------------------


def test_ask_closed_by_default_when_no_token_and_no_opt_in(
    transport: StaticTransport, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SARATHI_ALLOW_OPEN", raising=False)
    resp = _client(transport).post("/ask", json=QUESTION)
    assert resp.status_code == 401
    assert resp.json()["error"] == "auth_not_configured"
    assert "SARATHI_ALLOW_OPEN" in resp.json()["detail"]
    health = _client(transport).get("/health").json()
    assert health["auth_required"] is False and health["open_access"] is False


@pytest.mark.parametrize("val", ["0", "", "no", "false"])
def test_falsey_opt_in_values_do_not_open_it(
    transport: StaticTransport, monkeypatch: pytest.MonkeyPatch, val: str,
) -> None:
    monkeypatch.setenv("SARATHI_ALLOW_OPEN", val)
    assert _client(transport).post("/ask", json=QUESTION).status_code == 401


def test_opt_in_opens_it_and_health_says_so(transport: StaticTransport) -> None:
    c = _client(transport)   # conftest sets SARATHI_ALLOW_OPEN=1
    assert c.post("/ask", json=QUESTION).status_code == 200
    assert c.get("/health").json()["open_access"] is True


def test_a_token_beats_the_opt_in(
    transport: StaticTransport, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SARATHI_TOKEN", TOKEN)   # ALLOW_OPEN=1 still set
    c = _client(transport)
    assert c.post("/ask", json=QUESTION).status_code == 401
    assert c.get("/health").json()["open_access"] is False


def test_importing_the_module_needs_no_backend() -> None:
    """A fresh interpreter, no SUPABASE_*: import works, building ``app`` fails
    closed. (Subprocess, so the shared sarathi.app module is left untouched.)"""
    import os
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items()
           if k not in ("SUPABASE_URL", "SUPABASE_KEY", "YANTRA_ALLOW_DEMO_BACKEND")}
    code = ("import sarathi.app as m\n"
            "try:\n    m.app\nexcept Exception as e:\n"
            "    print(type(e).__name__)\n")
    out = subprocess.run([sys.executable, "-c", code], env=env, text=True,
                         capture_output=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "BackendNotConfigured"
