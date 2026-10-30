"""copy_demo_data: end to end against two in-process fake PostgREST servers."""
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).parent))
import copy_demo_data as cdd  # noqa: E402

_spec = importlib.util.spec_from_file_location("fk", ROOT / "e2e" / "fakerest.py")
fk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fk)


def _jwt(role):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b({'alg': 'HS256'})}.{b({'role': role})}.sig"


def test_only_service_role_keys_are_accepted():
    assert cdd.is_privileged_key(_jwt("service_role"))
    assert cdd.is_privileged_key("sb_secret_" + "a" * 30)
    assert not cdd.is_privileged_key(_jwt("anon"))
    assert not cdd.is_privileged_key("sb_publishable_abc")
    assert not cdd.is_privileged_key("")


def test_unsafe_rows_are_detected_but_normal_ones_pass():
    assert cdd.row_is_safe({"id": "AL-1", "msg": "AMR-05 pick retry at B4", "n": 3, "pos": [1.5, 2]})
    assert cdd.row_is_safe({"msg": "Robot didn't reach goal", "t": "2026-10-30T06:33:03+00:00"})
    for bad in ('<img src=x onerror=1>', "x');alert(1);//", "a`b", 'x onclick = y', "&#39;", "javascript:1"):
        assert not cdd.row_is_safe({"msg": bad}), bad
    assert not cdd.row_is_safe({"a": {"b": ["<b>"]}})


@pytest.fixture()
def servers():
    src, dst = fk.FakePostgREST(), fk.FakePostgREST()
    with src.lock:
        src.tables["robots"] = [{"id": f"AMR-{i:02d}", "vendor": "X", "status": "active"} for i in range(3)]
        src.tables["alerts"] = ([{"id": f"AL-{i}", "sev": "warn", "msg": "ok"} for i in range(5)]
                                + [{"id": "AL-evil", "sev": "crit", "msg": "<img src=x onerror=alert(1)>"}])
        src.tables["commands"] = [{"id": 1, "robot_id": "AMR-00", "cmd": "estop", "status": "approved"}]
        src.tables["robot_telemetry"] = [{"id": i, "robot_id": "AMR-00", "battery": 50 + i} for i in range(1, 4)]
    a, b = src.start(), dst.start()
    yield a, b, src, dst
    src.stop(); dst.stop()


def _run(monkeypatch, a, b, *extra, key=None):
    monkeypatch.setenv("YF_TARGET_URL", b)
    monkeypatch.setenv("YF_TARGET_SERVICE_KEY", key or _jwt("service_role"))
    return cdd.main(["--source-url", a, "--source-key", "sb_publishable_x", *extra])


def test_dry_run_writes_nothing(servers, monkeypatch, capsys):
    a, b, src, dst = servers
    assert _run(monkeypatch, a, b) == 0
    assert all(not dst.tables.get(t) for t in ("robots", "alerts", "robot_telemetry"))
    assert "dry run only" in capsys.readouterr().out


def test_apply_copies_safe_rows_and_never_commands(servers, monkeypatch):
    a, b, src, dst = servers
    assert _run(monkeypatch, a, b, "--apply") == 0
    assert len(dst.tables["robots"]) == 3
    assert {r["id"] for r in dst.tables["alerts"]} == {f"AL-{i}" for i in range(5)}   # AL-evil skipped
    assert not dst.tables.get("commands")
    tele = dst.tables["robot_telemetry"]
    assert len(tele) == 3 and [r["battery"] for r in tele] == [51, 52, 53]


def test_rerun_is_idempotent_for_keyed_tables_and_refuses_telemetry_dupes(servers, monkeypatch):
    a, b, src, dst = servers
    _run(monkeypatch, a, b, "--apply")
    _run(monkeypatch, a, b, "--apply")
    assert len(dst.tables["robots"]) == 3 and len(dst.tables["alerts"]) == 5


def test_refuses_publishable_key_and_same_project(servers, monkeypatch):
    a, b, *_ = servers
    assert _run(monkeypatch, a, b, "--apply", key="sb_publishable_zzz") == 2
    assert _run(monkeypatch, a, a, "--apply") == 2
