"""Per-request scope: which site the asker is looking at, and which
credential PostgREST should see (docs/WORKSPACES.md section 6).

The copilot used to read with its own anon key and no site filter. That is
fine for a demo-open box and wrong for self-serve workspaces, where the
answer must be "what THIS person is allowed to see in THIS workspace".
Two small pieces of per-request state carry that, kept in
:class:`contextvars.ContextVar` s rather than on the shared transport:

* ``site`` - every table query is filtered ``site_id=eq.<site>``;
* ``headers`` - extra PostgREST request headers derived from the asker's
  credentials: their Supabase JWT becomes ``Authorization: Bearer <jwt>``
  (the ``apikey`` stays the copilot's own anon key), a sandbox token
  becomes ``x-yf-demo-token``.

Why a ContextVar and not a parameter threaded through ``Transport.get``:
the transport interface is implemented by tests and by third parties with
the two-argument signature ``get(table, params)``, and one FastAPI app
serves every request from a shared thread pool. A ContextVar is isolated
per request (FastAPI runs each sync endpoint in a fresh copy of the
calling context) so two concurrent askers can never see each other's
token, and it needs no change to any transport that does not care.

THE COPILOT NEVER DECIDES WHAT IS VISIBLE. It forwards the credential;
row-level security (0007 / 0009 / 0019) decides. A forged ``site`` for a
workspace the asker does not belong to simply reads back zero rows, and a
junk token is dropped here (never forwarded) so it degrades to anon, which
RLS answers with nothing.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

#: Same shapes the database enforces: a site id is a short slug (this keeps
#: filter syntax out of the ``eq.`` value), a demo token is 32..128 hex
#: (0009's yf_demo_token), a user JWT is one opaque run of header-safe
#: characters.
SITE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
DEMO_TOKEN_RE = re.compile(r"^[0-9a-f]{32,128}$")
JWT_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,8192}$")

USER_TOKEN_HEADER = "x-yf-user-token"
DEMO_TOKEN_HEADER = "x-yf-demo-token"

_site: ContextVar[str | None] = ContextVar("sarathi_site", default=None)
_headers: ContextVar[dict[str, str]] = ContextVar("sarathi_headers", default={})


def current_site() -> str | None:
    """The site this request is scoped to, or None (unscoped, as before)."""
    return _site.get()


def current_headers() -> dict[str, str]:
    """Extra PostgREST headers for this request (a copy; empty by default)."""
    return dict(_headers.get())


def build_headers(user_token: str | None = None,
                  demo_token: str | None = None) -> dict[str, str]:
    """Map the asker's credentials onto PostgREST headers.

    Malformed values are dropped, not forwarded and not an error: the
    request then reads as plain anon and RLS shows it nothing.
    """
    out: dict[str, str] = {}
    user = (user_token or "").strip()
    if user.lower().startswith("bearer "):
        user = user[7:].strip()
    if user and JWT_RE.match(user):
        out["Authorization"] = f"Bearer {user}"
    demo = (demo_token or "").strip()
    if demo and DEMO_TOKEN_RE.match(demo):
        out[DEMO_TOKEN_HEADER] = demo
    return out


@contextmanager
def request_scope(site: str | None = None, user_token: str | None = None,
                  demo_token: str | None = None) -> Iterator[None]:
    """Run a block with this request's site and credentials in effect."""
    clean_site = site.strip() if isinstance(site, str) else None
    if clean_site is not None and not SITE_RE.match(clean_site):
        clean_site = None
    t_site = _site.set(clean_site or None)
    t_headers = _headers.set(build_headers(user_token, demo_token))
    try:
        yield
    finally:
        _headers.reset(t_headers)
        _site.reset(t_site)
