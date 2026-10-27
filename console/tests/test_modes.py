"""v0.13 console modes: the no-login mock demo, hash intents, workspace-less
Connect view. These need no backend at all — that is the point of demo mode.

Chromium discovery and fixtures come from conftest.py (``console_server``).
"""
from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")
pytest.importorskip("pytest_playwright")
from playwright.sync_api import Page, expect  # noqa: E402

from conftest import find_chromium  # noqa: E402

pytestmark = pytest.mark.skipif(
    find_chromium() is None, reason="no Chromium binary — browser tests skipped")


def _dead(console_server: str) -> str:
    # A backend that can never answer: proves demo mode makes no calls.
    return f"{console_server}/index.html?supa=http://127.0.0.1:9&key=x"


def test_hash_demo_opens_mock_console_without_signin(
        page: Page, console_server: str) -> None:
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    requests: list[str] = []
    page.on("request", lambda r: requests.append(r.url))
    page.goto(_dead(console_server) + "#demo")
    expect(page.locator("#banner")).to_contain_text("Demo with mock data")
    expect(page.locator("#cloud-lbl")).to_contain_text("mock data", timeout=10_000)
    assert page.locator("#signin.open").count() == 0   # modal is lazy: absent or closed
    expect(page.locator("#ov-health")).to_be_visible()
    page.locator("#nav button[data-v='liveops']").click()
    expect(page.locator("#fl-list")).to_contain_text("AMR-07")
    assert not [u for u in requests if u.startswith("http://127.0.0.1:9/")], \
        "demo mode must not call the backend"
    assert errors == [], errors


def test_query_demo_mode_equivalent(page: Page, console_server: str) -> None:
    page.goto(_dead(console_server) + "&mode=demo")
    expect(page.locator("#mode-pill")).to_contain_text("DEMO")
    expect(page.locator("#banner")).to_contain_text("Create free account")


def test_demo_banner_cta_opens_signup_tab(
        page: Page, console_server: str) -> None:
    page.goto(_dead(console_server) + "#demo")
    page.locator("#banner .btn.cta").click()
    expect(page.locator("#signin")).to_have_class(re.compile(r"\bopen\b"))
    expect(page.locator("#si-submit")).to_have_text("Create account")


def test_demo_copilot_answers_from_mock_story(
        page: Page, console_server: str) -> None:
    page.goto(_dead(console_server) + "#demo")
    page.keyboard.press("Control+j")
    page.locator("#cp-in").fill("Why did throughput drop after 14:00?")
    page.keyboard.press("Enter")
    expect(page.locator("#cp-body .msg.ai").last).to_contain_text(
        "localization", timeout=10_000)


def test_connect_view_shows_snippets_without_workspace(
        page: Page, console_server: str) -> None:
    page.goto(_dead(console_server) + "#demo")
    page.locator("#nav button[data-v='fleet']").click()
    view = page.locator("#v-fleet")
    expect(view).to_contain_text("Create free account")
    expect(view).to_contain_text("x-yf-ingest-key")
    page.get_by_role("button", name="REST (curl)").click()
    expect(view.locator(".codeblk")).to_contain_text("on_conflict=id")


def test_signup_hash_opens_account_modal_on_signup_tab(
        page: Page, console_server: str) -> None:
    page.goto(_dead(console_server) + "#signup")
    expect(page.locator("#signin")).to_have_class(
        re.compile(r"\bopen\b"), timeout=15_000)
    expect(page.locator("#si-submit")).to_have_text("Create account")
