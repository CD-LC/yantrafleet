"""Fail-closed backend resolution: a fork can never write to the demo by accident."""
import logging

import pytest

from yantracore.backend import (DEMO_KEY, DEMO_URL, BackendNotConfigured,
                                resolve_backend)


def test_explicit_args_win_and_trailing_slash_is_stripped():
    assert resolve_backend("https://a.test/", "k", environ={}) == ("https://a.test", "k")


def test_env_is_used():
    env = {"SUPABASE_URL": "https://e.test", "SUPABASE_KEY": "ek"}
    assert resolve_backend(environ=env) == ("https://e.test", "ek")


def test_args_beat_env():
    env = {"SUPABASE_URL": "https://e.test", "SUPABASE_KEY": "ek"}
    assert resolve_backend("https://a.test", "ak", environ=env) == ("https://a.test", "ak")


def test_nothing_configured_fails_closed_with_the_fix_in_the_message():
    with pytest.raises(BackendNotConfigured) as ei:
        resolve_backend(environ={})
    msg = str(ei.value)
    assert "SUPABASE_URL" in msg and "--loopback" in msg and "YANTRA_ALLOW_DEMO_BACKEND" in msg


def test_blank_values_count_as_unset():
    with pytest.raises(BackendNotConfigured):
        resolve_backend(environ={"SUPABASE_URL": "  ", "SUPABASE_KEY": ""})


@pytest.mark.parametrize("env", [{"SUPABASE_URL": "https://mine.test"},
                                 {"SUPABASE_KEY": "mine"}])
@pytest.mark.parametrize("optin", ["1", "true", "YES"])
def test_a_half_configuration_is_never_completed_from_the_demo(env, optin):
    # Pairing the user's URL with the demo key (or the reverse) would send
    # their data to, or authenticate them against, somebody else's project.
    with pytest.raises(BackendNotConfigured):
        resolve_backend(environ={**env, "YANTRA_ALLOW_DEMO_BACKEND": optin})


@pytest.mark.parametrize("val", ["0", "", "no", "false"])
def test_opt_in_must_be_truthy(val):
    with pytest.raises(BackendNotConfigured):
        resolve_backend(environ={"YANTRA_ALLOW_DEMO_BACKEND": val})


def test_opt_in_uses_demo_and_warns_loudly(caplog):
    with caplog.at_level(logging.WARNING, logger="yantracore.backend"):
        got = resolve_backend(environ={"YANTRA_ALLOW_DEMO_BACKEND": "1"})
    assert got == (DEMO_URL, DEMO_KEY)
    assert "PUBLIC DEMO BACKEND" in caplog.text and DEMO_URL in caplog.text
