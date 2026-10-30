"""CAPTCHA (Cloudflare Turnstile) on sign-in / sign-up.

Dormant with no site key: nothing loads, requests are unchanged. With a key
(<meta name="yf-captcha-sitekey">) the widget mounts in the account modal and
its one-time token travels as gotrue_meta_security.captcha_token. Turnstile is
stubbed - no network leaves localhost.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

CONSOLE_DIR = Path(__file__).resolve().parent.parent
KEY = "0x4AAAAAAAtestkey1234567"

# Stand-in for challenges.cloudflare.com: render() "solves" after a tick unless
# window.__noSolve is set; reset() clears and issues the next token.
STUB = """
(function(){
  var n = 0, cb = null;
  window.__resets = 0;
  function solve(){ if (!window.__noSolve && cb) { n += 1; cb('tok-' + n); } }
  window.turnstile = {
    render: function(el, o){ cb = o.callback; el.setAttribute('data-sitekey', o.sitekey); setTimeout(solve, 20); return 'w1'; },
    reset: function(){ window.__resets += 1; setTimeout(solve, 20); }
  };
})();
"""


@pytest.fixture(autouse=True)
def _quiet(page: Page):
    page.add_init_script("try{localStorage.setItem('yf_tour_done','1')}catch(e){}")


def _serve_with_key(page: Page, console_server: str, key: str) -> None:
    html = (CONSOLE_DIR / "index.html").read_text(encoding="utf-8").replace(
        '<meta name="yf-captcha-sitekey" content="">',
        f'<meta name="yf-captcha-sitekey" content="{key}">', 1)
    page.route(f"{console_server}/index.html**", lambda r: r.fulfill(
        status=200, content_type="text/html", body=html))


def _capture_token_posts(page: Page) -> list[dict]:
    posts: list[dict] = []

    def handler(route):
        try:
            posts.append(json.loads(route.request.post_data or "{}"))
        except Exception:
            posts.append({})
        route.fulfill(status=400, content_type="application/json",
                      body='{"error_description":"Invalid login credentials"}')

    page.route("**/auth/v1/token**", handler)
    return posts


def _open_and_submit(page: Page, email="a@b.co", pw="pw-123456") -> None:
    page.evaluate("YFAuth.setMode('in');YFAuth.show()")
    page.fill("#si-email", email)
    page.fill("#si-pass", pw)
    page.click("#si-submit")


def test_dormant_without_a_site_key(page: Page, console_server: str) -> None:
    loaded: list[str] = []
    page.route("https://challenges.cloudflare.com/**", lambda r: (loaded.append(r.request.url), r.abort()))
    posts = _capture_token_posts(page)
    page.goto(f"{console_server}/index.html?supa=http://127.0.0.1:9&key=k")
    assert page.evaluate("Captcha.enabled()") is False
    _open_and_submit(page)
    expect(page.locator("#si-err")).to_contain_text("Invalid login credentials")
    assert not loaded, "Turnstile must not load when no site key is configured"
    assert posts and "gotrue_meta_security" not in posts[0]


def test_token_is_attached_and_single_use(page: Page, console_server: str) -> None:
    page.route("https://challenges.cloudflare.com/**", lambda r: r.fulfill(
        status=200, content_type="application/javascript", body=STUB))
    _serve_with_key(page, console_server, KEY)
    posts = _capture_token_posts(page)
    page.goto(f"{console_server}/index.html?supa=http://127.0.0.1:9&key=k")
    assert page.evaluate("Captcha.enabled()") is True
    page.evaluate("YFAuth.show()")
    expect(page.locator("#si-captcha[data-sitekey]")).to_have_count(1)
    page.wait_for_function("Captcha.token === 'tok-1'")

    _open_and_submit(page)
    expect(page.locator("#si-err")).to_contain_text("Invalid login credentials")
    assert posts[0]["gotrue_meta_security"] == {"captcha_token": "tok-1"}
    assert page.evaluate("window.__resets") >= 1                   # token spent -> widget reset
    page.wait_for_function("Captcha.token === 'tok-2'")           # a fresh token, never reused

    page.click("#si-submit")
    expect(page.locator("#si-err")).to_contain_text("Invalid login credentials")
    assert posts[1]["gotrue_meta_security"] == {"captcha_token": "tok-2"}


def test_unsolved_captcha_blocks_the_request(page: Page, console_server: str) -> None:
    page.add_init_script("window.__noSolve = true")
    page.route("https://challenges.cloudflare.com/**", lambda r: r.fulfill(
        status=200, content_type="application/javascript", body=STUB))
    _serve_with_key(page, console_server, KEY)
    posts = _capture_token_posts(page)
    page.goto(f"{console_server}/index.html?supa=http://127.0.0.1:9&key=k")
    _open_and_submit(page)
    expect(page.locator("#si-err")).to_contain_text("CAPTCHA")
    assert posts == [], "no auth request may be sent without a solved CAPTCHA"


@pytest.mark.parametrize("bad", ["", "short", "has space in it!!", '"><script>x</script>'])
def test_malformed_site_keys_keep_it_off(page: Page, console_server: str, bad: str) -> None:
    html = (CONSOLE_DIR / "index.html").read_text(encoding="utf-8").replace(
        '<meta name="yf-captcha-sitekey" content="">',
        '<meta name="yf-captcha-sitekey" content="%s">' % bad.replace('"', "&quot;"), 1)
    page.route(f"{console_server}/index.html**", lambda r: r.fulfill(
        status=200, content_type="text/html", body=html))
    page.goto(f"{console_server}/index.html?supa=http://127.0.0.1:9&key=k")
    assert page.evaluate("Captcha.enabled()") is False
