"""Academy backend trust gate: a crafted link must not be able to send the
learner's password / JWT to a server the operator did not choose.

``?auth=`` is the sensitive one - it is where POST /auth/v1/token (the
password grant) and /auth/v1/signup go. Hermetic: nothing leaves localhost.
"""
from __future__ import annotations

import pytest
from playwright.sync_api import Page

DEFAULT_SUPA = "https://flwyvhsmgrrqpmhcqlzd.supabase.co"


@pytest.fixture()
def egress(page: Page):
    seen: list[str] = []

    def handler(route):
        seen.append(route.request.url)
        route.abort()

    page.route(lambda u: not u.startswith(("http://127.0.0.1", "http://localhost",
                                           "data:", "blob:", "about:")), handler)
    return seen


def test_crafted_link_cannot_redirect_the_password_grant(
        page: Page, academy_server: str, egress: list[str]) -> None:
    page.goto(f"{academy_server}/index.html?supa=https://evil.example&key=stolen"
              f"&auth=https://evil.example")
    assert page.evaluate("SUPA_URL") == DEFAULT_SUPA
    assert page.evaluate("AUTH_URL") == DEFAULT_SUPA
    assert page.evaluate("SUPA_KEY").startswith("sb_publishable_")
    assert not [u for u in egress if "evil.example" in u]


def test_auth_alone_cannot_be_pointed_at_a_stranger(
        page: Page, academy_server: str, egress: list[str]) -> None:
    page.goto(f"{academy_server}/index.html?auth=http://evil.example")
    assert "evil.example" not in page.evaluate("AUTH_URL")


def test_trusted_overrides_are_honoured(
        page: Page, academy_server: str, egress: list[str]) -> None:
    page.goto(f"{academy_server}/index.html?supa=https://abc123.supabase.co&key=pub"
              f"&auth=http://127.0.0.1:9")
    assert page.evaluate("SUPA_URL") == "https://abc123.supabase.co"
    assert page.evaluate("SUPA_KEY") == "pub"
    assert page.evaluate("AUTH_URL") == "http://127.0.0.1:9"


def test_token_and_bad_site_are_handled(
        page: Page, academy_server: str, egress: list[str]) -> None:
    page.goto(f"{academy_server}/index.html?site=x%27%3B1//&token=tok-9")
    assert page.evaluate("window.SITE") is None
    assert "tok-9" not in page.url
