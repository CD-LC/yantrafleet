"""FastAPI app — POST /ask on :8001.

CORS is wide open (including the ``null`` origin a file:// console sends)
because the API is read-only over client-safe data.

Optional bearer auth: when the ``SARATHI_TOKEN`` environment variable is
set at app creation, POST /ask requires ``Authorization: Bearer <token>``
and answers 401 (JSON) otherwise. GET /health stays open either way but
reports ``auth_required``. When the env var is unset, behaviour is
unchanged (fully open).

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

    # file:// pages send Origin: null — allow_origins=["*"] covers it as long
    # as credentials stay disabled (they do; the anon key is baked in).
    # SARATHI_CORS_ORIGINS="https://a.example,https://b.example" pins browsers
    # to named origins; unset keeps the open default (credentials stay off, so
    # a cross-site page cannot ride anyone's cookies - there are none).
    cors = [o.strip() for o in os.environ.get("SARATHI_CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors or ["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def _authorized(request: Request) -> bool:
        """True when no token is configured, or the caller presented it.

        Reads the live SARATHI_TOKEN (table override else env var) on
        every request instead of a snapshot taken at app-creation time, so
        an admin rotating the token from the console takes effect on the
        very next request.
        """
        token = request.app.state.settings_sync.get("SARATHI_TOKEN") or None
        if token is None:
            return True
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
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "detail": "missing or invalid bearer token "
                              "(Authorization: Bearer <SARATHI_TOKEN>)",
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
        payload["auth_required"] = (
            request.app.state.settings_sync.get("SARATHI_TOKEN") is not None
        )
        return payload

    return app


# Default ASGI entrypoint for `uvicorn sarathi.app:app --port 8001`. Only
# this module-level production entrypoint starts the pollers — create_app()
# itself never does, so every test that calls create_app() directly keeps
# getting inert, never-started SettingsSync/TablePoller objects (see
# create_app's docstring).
app = create_app()
app.state.settings_sync.start()
app.state.config_sync.start()
