"""Academy CAPTCHA: same contract as the console (dormant without a site key;
token attached and single-use with one). Turnstile is stubbed."""
from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import Page, expect

ACADEMY_DIR = Path(__file__).resolve().parent.parent
KEY = "0x4AAAAAAAtestkey1234567"
STUB = """
(function(){var n=0,cb=null;
  window.turnstile={render:function(el,o){cb=o.callback;setTimeout(function(){n++;cb('tok-'+n)},20);return 'w'},
                    reset:function(){setTimeout(function(){n++;cb('tok-'+n)},20)}};})();
"""


def _posts(page: Page) -> list[dict]:
    out: list[dict] = []

    def h(route):
        out.append(json.loads(route.request.post_data or "{}"))
        route.fulfill(status=400, content_type="application/json",
                      body='{"error_description":"Invalid login credentials"}')

    page.route("**/auth/v1/token**", h)
    return out


def _submit(page: Page) -> None:
    page.evaluate("AuthUI.setMode('in');AuthUI.open()")
    page.fill("#auth-em", "a@b.co")
    page.fill("#auth-pw", "pw-123456")
    page.click("#auth-submit")


def test_dormant_without_key(page: Page, academy_server: str) -> None:
    seen: list[str] = []
    page.route("https://challenges.cloudflare.com/**", lambda r: (seen.append(r.request.url), r.abort()))
    posts = _posts(page)
    page.goto(f"{academy_server}/index.html?supa=http://127.0.0.1:9&key=k")
    _submit(page)
    expect(page.locator("#auth-err")).to_contain_text("Invalid login credentials")
    assert not seen and posts and "gotrue_meta_security" not in posts[0]


def test_token_attached_when_enabled(page: Page, academy_server: str) -> None:
    html = (ACADEMY_DIR / "index.html").read_text(encoding="utf-8").replace(
        '<meta name="yf-captcha-sitekey" content="">',
        f'<meta name="yf-captcha-sitekey" content="{KEY}">', 1)
    page.route(f"{academy_server}/index.html**", lambda r: r.fulfill(
        status=200, content_type="text/html", body=html))
    page.route("https://challenges.cloudflare.com/**", lambda r: r.fulfill(
        status=200, content_type="application/javascript", body=STUB))
    posts = _posts(page)
    page.goto(f"{academy_server}/index.html?supa=http://127.0.0.1:9&key=k")
    page.evaluate("AuthUI.open()")
    page.wait_for_function("Captcha.token === 'tok-1'")
    _submit(page)
    expect(page.locator("#auth-err")).to_contain_text("Invalid login credentials")
    assert posts[0]["gotrue_meta_security"] == {"captcha_token": "tok-1"}
    page.wait_for_function("Captcha.token === 'tok-2'")
