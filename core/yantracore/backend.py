"""Where does fleet data go? One answer, and it fails closed.

Every component that talks to PostgREST/Supabase used to fall back to an
embedded URL and publishable key for the maintainers' demo project. That is
convenient and wrong for an open-source project: a fork, or a first-time user
who forgets ``SUPABASE_URL``, would silently write robot telemetry, alerts and
commands into somebody else's database.

The rule now, for every component (sim, connector, detector, notifier, copilot,
ops):

* ``--url/--key`` flag, else ``SUPABASE_URL`` / ``SUPABASE_KEY`` -- both must be
  present. A URL without a key (or the reverse) is an error; a user-supplied
  value is **never** paired with a demo value.
* Neither present: :class:`BackendNotConfigured`, with the fix in the message.
* Neither present *and* ``YANTRA_ALLOW_DEMO_BACKEND=1``: the public demo
  project is used, with a loud warning naming the destination. This is an
  explicit opt-in for people who really do want the shared demo.

Loopback mode (``yantraops up --loopback``) supplies its own local URL and is
unaffected.
"""
from __future__ import annotations

import logging
import os
from typing import Mapping

log = logging.getLogger("yantracore.backend")

#: The maintainers' public demo project. The key is the *publishable* (anon)
#: key: client-safe by design, its power is whatever RLS allows.
DEMO_URL = "https://mqrffzpaeqtngxcpttyx.supabase.co"
DEMO_KEY = "sb_publishable_mOjh5X1pbJUi7d6Iy0LgBA_o8kPDZI8"

ENV_URL = "SUPABASE_URL"
ENV_KEY = "SUPABASE_KEY"
ENV_ALLOW_DEMO = "YANTRA_ALLOW_DEMO_BACKEND"


class BackendNotConfigured(RuntimeError):
    """No backend was configured and the demo fallback was not opted into."""


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def resolve_backend(url: str | None = None, key: str | None = None, *,
                    environ: Mapping[str, str] | None = None) -> tuple[str, str]:
    """Return ``(base_url_without_trailing_slash, key)`` or raise."""
    env = os.environ if environ is None else environ
    url = (url or env.get(ENV_URL) or "").strip()
    key = (key or env.get(ENV_KEY) or "").strip()
    if url and key:
        return url.rstrip("/"), key
    if url or key:
        missing = ENV_KEY if url else ENV_URL
        raise BackendNotConfigured(
            f"{missing} is not set. Give both {ENV_URL} and {ENV_KEY} (or the "
            "matching --url/--key flags); a value of yours is never combined "
            "with the demo project's.")
    if _truthy(env.get(ENV_ALLOW_DEMO)):
        log.warning(
            "USING THE PUBLIC DEMO BACKEND %s (%s=1). Data you write goes to "
            "the maintainers' shared demo project, not to your own database.",
            DEMO_URL, ENV_ALLOW_DEMO)
        return DEMO_URL, DEMO_KEY
    raise BackendNotConfigured(
        f"No backend configured. Set {ENV_URL} and {ENV_KEY} to your own "
        "Supabase/PostgREST project (see docs/SECURITY.md), or run "
        "`yantraops up --loopback` for a local stack with no cloud. To use the "
        f"shared public demo on purpose, set {ENV_ALLOW_DEMO}=1.")
