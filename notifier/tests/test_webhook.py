"""WebhookChannel: Slack-compatible ``{"text": ...}`` payload shape."""
from __future__ import annotations

import json

import httpx

from yantranotify.channels import WebhookChannel

from conftest import FakeRest

HOOK = "https://hooks.example.test/services/T000/B000/XXX"


def test_payload_is_slack_compatible_json(rest: FakeRest):
    ch = WebhookChannel(url=HOOK, client=rest.client())
    assert ch.send("[CRIT] ALERT A-001: battery critical") is True
    assert len(rest.webhook_posts) == 1
    req = rest.webhook_posts[0]
    assert req.method == "POST"
    assert str(req.url) == HOOK
    assert req.headers["content-type"] == "application/json"
    body = json.loads(req.content.decode())
    assert body == {"text": "[CRIT] ALERT A-001: battery critical"}


def test_env_url_is_used(rest: FakeRest, monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", HOOK)
    ch = WebhookChannel(client=rest.client())
    ch.send("hello")
    assert len(rest.webhook_posts) == 1


def test_unset_url_prints_instead_of_posting(rest: FakeRest, monkeypatch, capsys):
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    ch = WebhookChannel(client=rest.client())
    assert ch.send("hello") is True
    assert rest.webhook_posts == []
    out = capsys.readouterr().out
    assert "WEBHOOK_URL unset" in out and "hello" in out


def test_dry_run_never_posts(rest: FakeRest, capsys):
    ch = WebhookChannel(url=HOOK, client=rest.client(), dry_run=True)
    assert ch.send("hello") is True
    assert rest.webhook_posts == []
    assert "dry-run" in capsys.readouterr().out


def test_http_error_is_swallowed_and_reported():
    def boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = httpx.Client(transport=httpx.MockTransport(boom))
    ch = WebhookChannel(url=HOOK, client=client)
    assert ch.send("hello") is False  # logged, not raised


# --- SSRF guard (yantracore.netguard) ---------------------------------------

def test_internal_webhook_target_is_refused_and_nothing_is_sent(rest: FakeRest, caplog):
    ch = WebhookChannel(url="https://internal.corp/hook", client=rest.client())
    assert ch.send("hi") is False
    assert rest.requests == []
    assert "SSRF guard" in caplog.text


def test_metadata_webhook_target_is_refused(rest: FakeRest):
    ch = WebhookChannel(url="https://meta.attacker.example/", client=rest.client())
    assert ch.send("hi") is False
    assert rest.requests == []


def test_literal_metadata_ip_and_plain_http_refused(rest: FakeRest):
    for url in ("http://169.254.169.254/latest/meta-data/",
                "http://hooks.example.test/x", "https://127.0.0.1:8001/ask"):
        assert WebhookChannel(url=url, client=rest.client()).send("x") is False
    assert rest.requests == []


def test_lan_webhook_allowed_only_with_operator_opt_in(rest: FakeRest, monkeypatch):
    ch = WebhookChannel(url="https://internal.corp/hook", client=rest.client())
    monkeypatch.setenv("YANTRA_OUTBOUND_ALLOW_HOSTS", "internal.corp")
    rest.handler = lambda r: httpx.Response(200)  # type: ignore[assignment]
    ch._client = httpx.Client(transport=httpx.MockTransport(rest.handler))
    assert ch.send("hi") is True


def test_default_client_never_follows_redirects():
    ch = WebhookChannel(url="https://hooks.example.test/x")
    assert ch._client.follow_redirects is False
