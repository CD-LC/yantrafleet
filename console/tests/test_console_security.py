"""Console security suite: the backend trust gate and stored-XSS containment.

Two attacks this guards against, both reachable by a stranger:

* A crafted LINK (``?supa= ?ask= ?door=``) that repoints the console at the
  attacker's server, so the victim's sign-in password / JWT / questions are
  sent there.
* A crafted ROW (alert text, robot id, command note...) written into a demo-open
  or sandbox database, rendered by the console into innerHTML / onclick="...".

Hermetic: the in-process fake PostgREST is the only backend; any request that
would leave localhost is aborted and counted.
"""
from __future__ import annotations

import importlib.util
import socket
import threading
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

CONSOLE_DIR = Path(__file__).resolve().parent.parent
FAKEREST_PY = CONSOLE_DIR.parent / "e2e" / "fakerest.py"

pytest.importorskip("playwright.sync_api")
pytest.importorskip("pytest_playwright")

_spec = importlib.util.spec_from_file_location("yf_fakerest_security", FAKEREST_PY)
assert _spec and _spec.loader
fakerest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fakerest)

DEFAULT_SUPA = "https://mqrffzpaeqtngxcpttyx.supabase.co"
EVIL = "https://evil.example"


def _now_iso(offset_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


def _dead_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _CORSHandler(fakerest._Handler):
    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "apikey, authorization, content-type, prefer, "
                         "x-yf-demo-token, x-yf-ingest-key")
        super().end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


class SecFake(fakerest.FakePostgREST):
    def start(self) -> str:
        store = self

        class Handler(_CORSHandler):
            fake = store

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="sec-fakerest", daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"


# Payloads: each tries to run script if the value reaches HTML unescaped.
IMG = '<img src=x onerror="window.__pwned=(window.__pwned||0)+1">'
BREAKOUT = "AMR-9');window.__pwned=(window.__pwned||0)+10;//"
ATTR = '" onmouseover="window.__pwned=(window.__pwned||0)+100" x="'
SCRIPT = "<script>window.__pwned=(window.__pwned||0)+1000</script>"


@pytest.fixture()
def hostile_fake():
    f = SecFake()
    with f.lock:
        f.tables["fleet_meta"] = [{
            "id": 1, "writer_id": "yantrasim-sec",
            "updated_at": _now_iso(3600), "sim_min": 1, "throughput": 1}]
        f.tables["robots"] = [{
            "id": BREAKOUT, "vendor": IMG, "status": "active", "battery": 50.0,
            "speed": 1.0, "task_kind": SCRIPT, "health": 90.0,
            "motor_temp": 40.0, "tasks_done": 1, "fw": ATTR}]
        f.tables["alerts"] = [{
            "id": "A-1", "sev": "crit", "msg": IMG, "src": BREAKOUT,
            "tlabel": SCRIPT, "ack": False}]
        f.tables["incidents"] = [{
            "id": BREAKOUT, "sev": "crit", "title": IMG, "src": BREAKOUT,
            "tlabel": ATTR, "state": "Open", "impact": SCRIPT, "rca": IMG,
            "fix": SCRIPT, "dur": "1m", "created_at": _now_iso(-60)}]
        f.tables["missions"] = [{
            "id": "M-1", "name": IMG, "robots": [BREAKOUT], "state": "Running",
            "prog": 10, "eta": SCRIPT}]
        f.tables["commands"] = [{
            "id": 1, "robot_id": BREAKOUT, "cmd": "estop", "status": "pending",
            "requested_by": IMG, "note": SCRIPT, "created_at": _now_iso(-30)}]
    base = f.start()
    yield base, f
    f.stop()


@pytest.fixture(autouse=True)
def _quiet(page: Page):
    page.add_init_script("try{localStorage.setItem('yf_tour_done','1')}catch(e){}")


@pytest.fixture()
def egress(page: Page):
    """Abort anything that is not localhost and remember what was tried."""
    seen: list[str] = []

    def handler(route):
        seen.append(route.request.url)
        route.abort()

    page.route(lambda u: not u.startswith(("http://127.0.0.1", "http://localhost",
                                           "data:", "blob:", "about:")), handler)
    return seen


# ------------------------------------------------------------ backend gate

def test_crafted_link_cannot_repoint_the_console(
        page: Page, console_server: str, egress: list[str]) -> None:
    page.goto(f"{console_server}/index.html?supa={EVIL}&key=stolen"
              f"&ask={EVIL}/ask&door={EVIL}&auth={EVIL}")
    assert page.evaluate("SUPA_URL") == DEFAULT_SUPA
    assert page.evaluate("SUPA_KEY").startswith("sb_publishable_")
    assert page.evaluate("DOOR_BASE") != EVIL
    page.evaluate("Copilot.resolveUrls()")
    assert "evil.example" not in page.evaluate("Copilot.SARATHI_URL")
    assert "evil.example" not in page.evaluate("Copilot.SARATHI_HEALTH_URL")
    expect(page.locator(".toast", has_text="Ignored untrusted")).to_be_visible(timeout=5_000)
    assert not [u for u in egress if "evil.example" in u], \
        "the console contacted the attacker's host"


@pytest.mark.parametrize("bad", [
    "http://evil.example",            # cleartext + unknown
    "https://evil.example",           # unknown https
    "https://supabase.co.evil.example",  # suffix trick
    "https://evilsupabase.co",        # not a *.supabase.co subdomain
    "javascript:alert(1)",
    "ftp://127.0.0.1",
    "not a url",
])
def test_untrusted_backend_forms_are_rejected(
        page: Page, console_server: str, egress: list[str], bad: str) -> None:
    page.goto(f"{console_server}/index.html?supa={bad}&key=stolen")
    assert page.evaluate("SUPA_URL") == DEFAULT_SUPA
    assert page.evaluate("SUPA_KEY") != "stolen"


def test_trusted_overrides_are_honoured(
        page: Page, console_server: str, egress: list[str]) -> None:
    page.goto(f"{console_server}/index.html?supa=https://abc123.supabase.co&key=pub-key")
    assert page.evaluate("SUPA_URL") == "https://abc123.supabase.co"
    assert page.evaluate("SUPA_KEY") == "pub-key"
    port = _dead_port()
    page.goto(f"{console_server}/index.html?supa=http://127.0.0.1:{port}&key=k2")
    assert page.evaluate("SUPA_URL") == f"http://127.0.0.1:{port}"
    assert page.evaluate("SUPA_KEY") == "k2"


def test_operator_allowlist_meta_admits_a_custom_domain(
        page: Page, console_server: str, egress: list[str]) -> None:
    """nginx injects the box's SUPABASE_URL into <meta name=yf-allowed-hosts>;
    simulate that and check a non-supabase.co backend is then accepted."""
    page.route(f"{console_server}/index.html**", lambda r: r.fulfill(
        status=200, content_type="text/html",
        body=(CONSOLE_DIR / "index.html").read_text(encoding="utf-8").replace(
            '<meta name="yf-allowed-hosts" content="">',
            '<meta name="yf-allowed-hosts" content="https://db.mycorp.example">', 1)))
    page.goto(f"{console_server}/index.html?supa=https://db.mycorp.example&key=k")
    assert page.evaluate("SUPA_URL") == "https://db.mycorp.example"


def test_bad_site_param_is_dropped(page: Page, console_server: str,
                                   egress: list[str]) -> None:
    page.goto(f"{console_server}/index.html?site=x%27%3Balert(1)//&mode=demo")
    assert page.evaluate("window.SITE") is None


def test_token_is_scrubbed_from_the_address_bar(
        page: Page, console_server: str, egress: list[str]) -> None:
    page.goto(f"{console_server}/index.html?supa=http://127.0.0.1:{_dead_port()}"
              f"&key=k&token=tok-secret")
    assert "tok-secret" not in page.url and "token=" not in page.url
    assert page.evaluate("Copilot.SARATHI_TOKEN") == "tok-secret"
    page.reload()                                  # still usable after a reload
    assert page.evaluate("Copilot.SARATHI_TOKEN") == "tok-secret"


# ------------------------------------------------------------ stored XSS

def test_hostile_rows_never_execute(
        page: Page, console_server: str, hostile_fake, egress: list[str]) -> None:
    base, _ = hostile_fake
    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.goto(f"{console_server}/index.html?supa={base}&key=test&site=BLR-DC1")
    expect(page.locator("#cloud-lbl")).to_contain_text("LIVE", timeout=15_000)

    # Walk every view that renders table rows, then poke the clickable ones.
    for view in ("overview", "liveops", "incidents", "missions", "maint",
                 "analytics", "audit"):
        page.locator(f"#nav button[data-v='{view}']").click()
        page.wait_for_timeout(2500)   # past one poll cycle so rows are rendered
        for sel in ("tr.click", ".robot-dot", ".evd", ".al .btn"):
            for el in page.locator(sel).all()[:3]:
                try:
                    el.click(timeout=800)
                except Exception:
                    pass
        page.mouse.move(5, 5)

    assert page.evaluate("window.__pwned") is None, \
        "a hostile row executed script in the console"
    assert not dialogs
    # No injected element exists anywhere in the DOM.
    assert page.locator("img[src='x']").count() == 0
    assert page.locator("script", has_text="__pwned").count() == 0
    assert page.locator("[onmouseover*='__pwned']").count() == 0
    # ...and the row data did arrive (this is a real render, not an empty page).
    assert page.evaluate("store.alerts.length") >= 1


def test_defang_preserves_ids_and_numbers(page: Page, console_server: str,
                                          egress: list[str]) -> None:
    page.goto(f"{console_server}/index.html?mode=demo")
    out = page.evaluate("""() => _defang({
      id: 'WS-0a1b2c3d-R01', ts: '2026-10-30T12:00:00.123+00:00', n: 42.5,
      ok: true, none: null, list: ['AMR-01', 'a<b'], nested: {k: "it's"}})""")
    assert out["id"] == "WS-0a1b2c3d-R01"
    assert out["ts"] == "2026-10-30T12:00:00.123+00:00"
    assert out["n"] == 42.5 and out["ok"] is True and out["none"] is None
    assert out["list"] == ["AMR-01", "a‹b"]
    assert out["nested"]["k"] == "it’s"
