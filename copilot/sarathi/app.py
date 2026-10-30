"""FastAPI app — POST /ask on :8001.

Secure by default (both are explicit opt-outs, never silent):

* **Auth.** ``POST /ask`` needs ``Authorization: Bearer <SARATHI_TOKEN>``.
  With no token configured it answers 401 ``auth_not_configured`` -- unless
  the operator sets ``SARATHI_ALLOW_OPEN=1`` to run it anonymously (loopback
  demos, or a public demo box where the rate limit is the guard). Every
  answer can cost an LLM call, so "open unless configured" was the wrong
  default. ``GET /health`` stays open and reports ``auth_required`` and
  ``open_access``.
* **CORS.** Only loopback origins (any port) are allowed by default. Name
  other origins in ``SARATHI_CORS_ORIGINS`` (comma-separated). The ``null``
  origin a ``file://`` page sends, and ``*``, are honoured only when listed
  there explicitly: ``SARATHI_CORS_ORIGINS=null``.

Run:  uvicorn sarathi.app:app --port 8001
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from collections import OrderedDict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from yantracore.runtime_config import TablePoller

from . import __version__
from .config import Settings, load_settings
from .service import CopilotService
from .settings_sync import SettingsSync
from .transport import SupabaseTransport, Transport

#: v0.18: non-secret runtime tunables this service reads live from
#: public.app_config (see supabase/0018_app_config.sql).
CONFIG_KEYS = ("SARATHI_LOW_BATTERY_THRESHOLD",)


#: Origins allowed without configuration: this machine only, any port.
LOOPBACK_ORIGIN_RE = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$"


def open_access() -> bool:
    """Operator explicitly allowed anonymous ``/ask`` (SARATHI_ALLOW_OPEN)."""
    return os.environ.get("SARATHI_ALLOW_OPEN", "").strip().lower() in (
        "1", "true", "yes", "on")


#: Per-client ceiling on POST /ask (requests per minute). Every answer can cost
#: an LLM call, and the endpoint is open unless SARATHI_TOKEN is set, so an
#: unthrottled /ask is a free way to spend the operator's quota. 0 disables.
DEFAULT_RATE_PER_MIN = 60
#: Distinct client keys remembered; bounded so the limiter cannot itself be
#: grown into a memory DoS by an address-spraying client.
RATE_TABLE_MAX = 10_000


class RateLimiter:
    """Sliding-window limiter, ``limit`` hits per ``window_s`` per key."""

    def __init__(self, limit: int, window_s: float = 60.0,
                 clock=time.monotonic) -> None:
        self.limit, self.window_s, self._clock = limit, window_s, clock
        self._hits: OrderedDict[str, deque] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        """None if allowed (and counted); else seconds until a slot frees."""
        if self.limit <= 0:
            return None
        now = self._clock()
        with self._lock:
            q = self._hits.pop(key, None) or deque()
            while q and now - q[0] >= self.window_s:
                q.popleft()
            if len(q) >= self.limit:
                self._hits[key] = q
                return max(0.0, self.window_s - (now - q[0]))
            q.append(now)
            self._hits[key] = q
            while len(self._hits) > RATE_TABLE_MAX:
                self._hits.popitem(last=False)
            return None


def client_key(request: Request, hops: int) -> str:
    """The caller's address. ``X-Forwarded-For`` is honoured only for as many
    trusted reverse proxies as the operator declares (``hops``; 0 = ignore the
    header, so it cannot be spoofed into a fresh quota). With hops=N the real
    client is the Nth entry from the right - the one our outermost trusted
    proxy actually saw."""
    peer = request.client.host if request.client else "?"
    if hops <= 0:
        return peer
    parts = [p.strip() for p in (request.headers.get("x-forwarded-for") or "").split(",") if p.strip()]
    return parts[-hops] if len(parts) >= hops else peer


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    #: Optional workspace / site the question is about (docs/WORKSPACES.md
    #: section 6). A short slug - it ends up in a PostgREST ``eq.`` filter.
    site: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


class EvidenceItem(BaseModel):
    label: str
    ref: str


class AskResponse(BaseModel):
    answer: str
    evidence: list[EvidenceItem]
    tier: str
    grounding: str
    meta: dict
    latency_ms: int


def create_app(
    transport: Transport | None = None,
    settings: Settings | None = None,
    completion_fn=None,
    settings_sync: SettingsSync | None = None,
    config_sync: TablePoller | None = None,
) -> FastAPI:
    """App factory. Tests pass a StaticTransport (and optionally a fake
    ``completion_fn`` for the LLM seam); production uses Supabase +
    litellm.

    ``settings_sync``/``config_sync`` are constructed but never
    ``.start()``-ed here — see the module-level entrypoint at the bottom
    of this file, which is the only place that starts the background
    pollers. Tests that don't pass one get a real-but-never-started
    object whose overrides stay empty forever, so ``.get(key)`` degrades
    to ``os.environ.get(key)`` (settings_sync) or the hardcoded default
    (config_sync) — identical to today's behaviour, no test changes
    required.
    """
    settings = settings or load_settings()
    transport = transport or SupabaseTransport(
        settings.supabase_url, settings.supabase_key
    )
    settings_sync = settings_sync or SettingsSync(
        settings.supabase_url, settings.supabase_key
    )
    config_sync = config_sync or TablePoller(
        settings.supabase_url, settings.supabase_key,
        table="app_config", keys=CONFIG_KEYS,
    )
    service = CopilotService(
        settings, transport, completion_fn=completion_fn,
        settings_sync=settings_sync, config_sync=config_sync,
    )

    app = FastAPI(title="sarathi", version=__version__)
    app.state.service = service
    app.state.limiter = RateLimiter(int(os.environ.get("SARATHI_RATE_PER_MIN", DEFAULT_RATE_PER_MIN)))
    app.state.proxy_hops = int(os.environ.get("SARATHI_TRUSTED_PROXY_HOPS", "0"))
    app.state.settings_sync = settings_sync
    app.state.config_sync = config_sync

    # Default: loopback origins only. "null" (file:// pages) and "*" must be
    # listed in SARATHI_CORS_ORIGINS on purpose. Credentials stay off.
    cors = [o.strip() for o in os.environ.get("SARATHI_CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors,
        allow_origin_regex=LOOPBACK_ORIGIN_RE,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def _authorized(request: Request) -> bool:
        """True when the caller presented the token, or open access was
        explicitly enabled and no token is configured.

        Reads the live SARATHI_TOKEN (table override else env var) on
        every request instead of a snapshot taken at app-creation time, so
        an admin rotating the token from the console takes effect on the
        very next request.
        """
        token = request.app.state.settings_sync.get("SARATHI_TOKEN") or None
        if token is None:
            return open_access()
        supplied = request.headers.get("authorization") or ""
        # Constant-time comparison of the full header vs the expectation:
        # covers wrong scheme, wrong token, and absent header alike.
        return hmac.compare_digest(
            supplied.encode("utf-8"), f"Bearer {token}".encode("utf-8")
        )

    @app.post("/ask", response_model=AskResponse)
    def ask(req: AskRequest, request: Request):
        wait = request.app.state.limiter.check(
            client_key(request, request.app.state.proxy_hops))
        if wait is not None:
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited",
                         "detail": "too many questions; slow down"},
                headers={"Retry-After": str(int(wait) + 1)},
            )
        if not _authorized(request):
            unconfigured = (request.app.state.settings_sync.get("SARATHI_TOKEN")
                            or None) is None
            return JSONResponse(
                status_code=401,
                content={
                    "error": "auth_not_configured" if unconfigured else "unauthorized",
                    "detail": ("the server has no SARATHI_TOKEN; set one, or "
                               "SARATHI_ALLOW_OPEN=1 to allow anonymous access"
                               if unconfigured else
                               "missing or invalid bearer token "
                               "(Authorization: Bearer <SARATHI_TOKEN>)"),
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
        t0 = time.perf_counter()
        # The asker's own credentials, if the console forwarded them: the
        # copilot then reads as that person (RLS decides what they see).
        result = request.app.state.service.ask(
            req.question.strip(), site=req.site,
            user_token=request.headers.get("x-yf-user-token"),
            demo_token=request.headers.get("x-yf-demo-token"),
        )
        return AskResponse(
            answer=result.answer,
            evidence=[EvidenceItem(**e) for e in result.evidence],
            tier=result.tier,
            grounding=result.grounding,
            meta=result.meta,
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    @app.get("/health")
    def health(request: Request) -> dict:
        payload = request.app.state.service.health()
        has_token = request.app.state.settings_sync.get("SARATHI_TOKEN") is not None
        payload["auth_required"] = has_token
        payload["open_access"] = (not has_token) and open_access()
        return payload

    return app


# Default ASGI entrypoint for `uvicorn sarathi.app:app --port 8001`. Only
# this module-level production entrypoint starts the pollers — create_app()
# itself never does, so every test that calls create_app() directly keeps
# getting inert, never-started SettingsSync/TablePoller objects (see
# create_app's docstring).
#
# Built lazily (PEP 562) so merely importing this module -- tests, tooling --
# does not require a configured backend (SUPABASE_URL/KEY fail closed); uvicorn
# resolves ``app`` by getattr and gets the same started instance every time.
_app: FastAPI | None = None


def __getattr__(name: str):
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
            _app.state.settings_sync.start()
            _app.state.config_sync.start()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
