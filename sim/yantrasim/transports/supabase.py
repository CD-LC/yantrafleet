"""Supabase (PostgREST) transport: bulk upsert robots, insert alerts.

Free-tier friendly per the Supabase spec:
  * one bulk POST per table per tick (single transaction each)
  * ``Prefer: resolution=merge-duplicates, return=minimal`` for upserts
  * ``resolution=ignore-duplicates`` for alerts, whose deterministic ids
    make retries idempotent
The anon (publishable) key is client-safe and embedded as a default;
override with env vars SUPABASE_URL / SUPABASE_KEY or CLI flags.

An injectable ``httpx.Client`` keeps every test offline
(``httpx.MockTransport``) — supabase.co is never reached in CI.

v0.17: :meth:`SupabaseTransport.poll_commands` is site-scoped. It runs
only ``approved`` commands whose ``site_id`` matches this executor's own
site (``site=`` / ``YANTRA_SITE_ID`` / ``BLR-DC1`` — the same resolution
that stamps every row this transport writes), because the service key it
usually carries bypasses RLS and would otherwise execute a command an
anonymous demo-sandbox visitor queued. ``site="*"`` opts out loudly.

v0.13 workspaces (supabase/0019, docs/WORKSPACES.md): with an INGEST KEY
(``ingest_key=`` / ``--ingest-key`` / ``YANTRA_INGEST_KEY``) this
transport writes as a self-serve workspace's own robot connector — the
anon key plus ``x-yf-ingest-key`` on every request, which 0019's RLS
resolves to exactly one ``WS-*`` site. Three things follow, all
automatic once a key is configured: the site MUST be that workspace
(``WS-<8 hex>``; anything else refuses to start), every robot / alert /
mission / telemetry id is prefixed ``<site>-`` because ``robots.id`` is a
global primary key shared by every tenant, and ``fleet_meta`` is never
written (it has no ``site_id``, so a key cannot reach it — logged once).
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from yantracore import site_id as _default_site_id

from ..sim import TickOutput
from ..translate import alert_row, fleet_meta_row, robot_row, telemetry_row

log = logging.getLogger(__name__)

DEFAULT_URL = "https://mqrffzpaeqtngxcpttyx.supabase.co"
DEFAULT_KEY = "sb_publishable_mOjh5X1pbJUi7d6Iy0LgBA_o8kPDZI8"

#: Explicit, deliberate opt-out of the command site filter. See
#: :func:`resolve_site` and ``docs/SECURITY.md``.
ANY_SITE = "*"

#: 0019 ingest-key contract (public.yf_ingest_key / yf_is_workspace_site).
#: Duplicated here rather than imported from yantraops: the simulator is a
#: standalone package a customer may run with nothing else installed.
INGEST_KEY_HEADER = "x-yf-ingest-key"
INGEST_KEY_ENV = "YANTRA_INGEST_KEY"
INGEST_KEY_RE = re.compile(r"^yk_[0-9a-f]{64}$")
WS_SITE_RE = re.compile(r"^WS-[0-9a-f]{8}$")


def resolve_config(url: str | None = None, key: str | None = None) -> tuple[str, str]:
    """Precedence: explicit arg > env var > embedded default."""
    return (
        (url or os.environ.get("SUPABASE_URL") or DEFAULT_URL).rstrip("/"),
        key or os.environ.get("SUPABASE_KEY") or DEFAULT_KEY,
    )


def resolve_ingest_key(key: str | None = None) -> str | None:
    """Explicit arg > ``YANTRA_INGEST_KEY`` > None (no workspace mode)."""
    return (key or os.environ.get(INGEST_KEY_ENV) or "").strip() or None


def check_ingest_config(key: str | None, site: str) -> None:
    """Refuse to start with a key that cannot work.

    A malformed key would be plain anon to 0019's RLS (every write 401s),
    and a key with a non-workspace site would stamp rows the policy then
    refuses (``site_id = yf_ingest_site()`` can only ever be the key's own
    ``WS-*`` site). Both are configuration mistakes worth a loud exit at
    startup rather than a warning per tick forever.
    """
    if key is None:
        return
    if not INGEST_KEY_RE.match(key):
        raise ValueError(
            "ingest key is malformed — expected 'yk_' followed by 64 lowercase "
            "hex characters, as workspace_create_ingest_key() returns it")
    if not WS_SITE_RE.match(site):
        raise ValueError(
            f"an ingest key writes exactly one self-serve workspace, and {site!r} "
            "is not one — pass --site WS-<8 hex> (or set YANTRA_SITE_ID) to the "
            "workspace the key was created in (see docs/WORKSPACES.md)")


def namespace_rows(table: str, rows: list[dict[str, Any]],
                   site: str) -> list[dict[str, Any]]:
    """Prefix every id a workspace writer emits with ``<site>-``.

    ``robots.id``, ``alerts.id`` and ``missions.id`` are global text
    primary keys shared by every tenant of one project, so two workspaces
    that both own an ``AMR-01`` must not collide. The console strips the
    prefix for display. References are rewritten consistently (telemetry
    and alert ``src`` point at the prefixed robot id, a mission's crew list
    too) so nothing in the workspace dangles, and ``site_id`` is forced to
    the workspace regardless of what ``yantracore.site_id()`` says — the
    policy would refuse anything else anyway.
    """
    prefix = f"{site}-"

    def pre(value: Any) -> Any:
        if isinstance(value, str) and value and not value.startswith(prefix):
            return prefix + value
        return value

    out = []
    for row in rows:
        r = dict(row)
        if table in ("robots", "alerts", "missions") and "id" in r:
            r["id"] = pre(r["id"])
        if table == "robot_telemetry":
            r["robot_id"] = pre(r.get("robot_id"))
        if table == "alerts" and r.get("src") not in (None, "", "fleet"):
            r["src"] = pre(r["src"])
        if table == "missions" and isinstance(r.get("robots"), list):
            r["robots"] = [pre(x) for x in r["robots"]]
        r["site_id"] = site
        out.append(r)
    return out


def strip_namespace(robot_id: str, site: str) -> str:
    """The inverse of :func:`namespace_rows` for an id read back."""
    prefix = f"{site}-"
    return robot_id[len(prefix):] if robot_id.startswith(prefix) else robot_id


def resolve_site(site: str | None = None) -> str:
    """The one site whose approved commands this executor may run.

    Precedence: explicit arg > ``YANTRA_SITE_ID`` > ``BLR-DC1``, i.e.
    exactly ``yantracore.site_id()`` — the SAME resolution
    ``yantrasim.translate`` already uses to stamp ``site_id`` on every
    row this transport writes. That is deliberate and is what makes the
    filter safe to switch on by default: a simulator polls commands for
    precisely the site it publishes into, so no existing deployment
    stops executing commands because of it.

    ``"*"`` disables the filter (pre-v0.17 behaviour). It has to be
    typed out, and it is logged as a warning every time.
    """
    resolved = (site or "").strip() or _default_site_id()
    return resolved


class SupabaseTransport:
    """Translates each tick to table rows and POSTs them via PostgREST."""

    def __init__(
        self,
        url: str | None = None,
        key: str | None = None,
        writer_id: str = "yantrasim",
        client: httpx.Client | None = None,
        timeout_s: float = 10.0,
        history_every: int = 3,
        site: str | None = None,
        ingest_key: str | None = None,
    ) -> None:
        self.base_url, self.key = resolve_config(url, key)
        self.rest = f"{self.base_url}/rest/v1"
        self.writer_id = writer_id
        self.history_every = history_every
        self.site = resolve_site(site)
        #: 0019: the workspace ingest key, or None for the classic
        #: service/anon-key writer. Validated against the site up front.
        self.ingest_key = resolve_ingest_key(ingest_key)
        check_ingest_config(self.ingest_key, self.site)
        self._warned_missing_site = False
        self._logged_fleet_meta_skip = False
        self._client = client or httpx.Client(timeout=timeout_s)
        if self.ingest_key:
            log.info("workspace mode: writing site %s with an ingest key — "
                     "ids namespaced '%s-', fleet_meta skipped", self.site,
                     self.site)
        if self.site == ANY_SITE:
            log.warning(
                "command gate: site filter DISABLED (site='%s') — this "
                "executor will run approved commands from EVERY site, "
                "including an anonymous demo sandbox if 0009 is applied. "
                "See docs/SECURITY.md.", ANY_SITE)
        else:
            log.info("command gate: only approved commands at site %r "
                     "will be executed", self.site)

    # -- Transport protocol ------------------------------------------------

    def publish(self, out: TickOutput) -> None:
        ts = out.states[0]["timestamp"] if out.states else ""
        rows = [robot_row(s, out.extras[self._rid(s, out)]) for s in out.states]
        self._post("robots", self._shape("robots", rows), on_conflict="id",
                   merge=True)
        if out.events:
            alerts = [alert_row(e, ts) for e in out.events]
            self._post("alerts", self._shape("alerts", alerts),
                       on_conflict="id", merge=False)
        if self.ingest_key:
            # fleet_meta has no site_id: 0019 keeps it off-limits to a key,
            # and there is nothing to scope it by. Said once, not per tick.
            if not self._logged_fleet_meta_skip:
                self._logged_fleet_meta_skip = True
                log.info("workspace mode: fleet_meta heartbeat skipped (the "
                         "table has no site_id; an ingest key cannot write it)")
        else:
            meta = fleet_meta_row(self.writer_id, out.sim_time_s,
                                  out.throughput_per_h, ts)
            self._post("fleet_meta", [meta], on_conflict="id", merge=True)
        # v0.5: missions snapshot — rows are already table-shaped
        # (id,name,robots,state,prog,eta,created_at); merge keeps progress
        # updates idempotent under retries.
        if out.missions:
            self._post("missions", self._shape("missions", out.missions),
                       on_conflict="id", merge=True)
        # v0.3: downsampled history for replay/analytics (every Nth tick).
        if self.history_every and out.tick % self.history_every == 0:
            samples = [telemetry_row(s, out.extras[self._rid(s, out)], ts)
                       for s in out.states]
            self._insert("robot_telemetry", self._shape("robot_telemetry", samples))

    def _shape(self, table: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Workspace namespacing when a key is configured, else untouched."""
        if not self.ingest_key:
            return rows
        return namespace_rows(table, rows, self.site)

    def _insert(self, table: str, rows: list) -> None:
        """Append-only insert (history tables); failures logged, not fatal."""
        try:
            resp = self._client.post(
                f"{self.rest}/{table}", json=rows,
                headers={**self._headers(), "Prefer": "return=minimal"},
            )
            if resp.status_code >= 400:
                log.warning("supabase %s INSERT -> %s: %s",
                            table, resp.status_code, resp.text[:200])
        except httpx.HTTPError as exc:
            log.warning("supabase %s INSERT failed: %s", table, exc)

    def _headers(self) -> dict[str, str]:
        h = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        if self.ingest_key:
            h[INGEST_KEY_HEADER] = self.ingest_key
        return h

    def poll_commands(self, apply_fn) -> int:
        """v0.2 human-in-the-loop gate, executor side.

        Fetch ``approved`` commands **for this executor's site**, apply each
        via ``apply_fn(robot_id, cmd) -> (ok, detail)``, and PATCH the row to
        ``executed`` / ``failed`` with the detail in ``note``. Returns how
        many were processed. Network errors are logged and swallowed — the
        sim never dies because the gate is unreachable.

        v0.17, SECURITY: the ``site_id`` filter is no longer optional. This
        transport normally runs with the service key, which BYPASSES RLS, so
        without a filter it would happily execute a row an anonymous demo
        sandbox visitor queued for a real robot (see
        supabase/0017_demo_command_scope.sql). Two independent controls:
        the query is filtered server-side, and every row that comes back is
        re-checked here before ``apply_fn`` is called. Set
        ``site=ANY_SITE`` ("*") to opt out deliberately.
        """
        params = {"status": "eq.approved", "order": "created_at.asc",
                  "limit": "20", "select": "id,robot_id,cmd,site_id"}
        if self.site != ANY_SITE:
            params["site_id"] = f"eq.{self.site}"
        try:
            resp = self._client.get(
                f"{self.rest}/commands",
                params=params,
                headers=self._headers(),
            )
            resp.raise_for_status()
            rows = resp.json() or []
        except Exception as exc:  # noqa: BLE001 - availability over purity
            log.warning("command poll failed: %s", exc)
            return 0
        rows = [row for row in rows if self._site_ok(row)]
        done = 0
        for row in rows:
            robot_id = str(row.get("robot_id") or "")
            if self.ingest_key:
                # The console queued the command against the namespaced id
                # (WS-xxxx-AMR-01); the simulator knows the robot as AMR-01.
                robot_id = strip_namespace(robot_id, self.site)
            ok, detail = apply_fn(robot_id, row.get("cmd", ""))
            body = {"status": "executed" if ok else "failed", "note": detail,
                    "executed_at": datetime.now(timezone.utc).isoformat()}
            try:
                self._client.patch(
                    f"{self.rest}/commands",
                    params={"id": f"eq.{row['id']}"},
                    json=body,
                    headers=self._headers(),
                ).raise_for_status()
            except Exception as exc:  # noqa: BLE001
                log.warning("command ack failed for %s: %s", row.get("id"), exc)
            done += 1
            log.info("command %s %s -> %s: %s", row.get("cmd"),
                     row.get("robot_id"), body["status"], detail)
        return done

    def _site_ok(self, row: dict[str, Any]) -> bool:
        """Client-side half of the site gate — never trust the projection.

        A row whose ``site_id`` disagrees with this executor's site is
        dropped and logged: reaching here means the server-side filter was
        not honoured (a stale PostgREST, a proxy that dropped the query
        string, a stand-in backend), which is precisely the situation the
        second control exists for.

        A row with NO ``site_id`` key at all is a backend that did not
        return the column rather than a mismatch — those are still applied,
        with a one-time warning, because refusing them would silently stop
        an executor pointed at an older backend. The server-side filter is
        the control in that case.
        """
        if self.site == ANY_SITE:
            return True
        if "site_id" not in row:
            if not self._warned_missing_site:
                self._warned_missing_site = True
                log.warning(
                    "command poll: backend returned no site_id column — the "
                    "server-side site filter (site_id=eq.%s) is the only "
                    "control on this connection", self.site)
            return True
        if row.get("site_id") != self.site:
            log.warning(
                "command %s REFUSED: it belongs to site %r, this executor "
                "serves %r (the backend ignored the site filter)",
                row.get("id"), row.get("site_id"), self.site)
            return False
        return True

    def close(self) -> None:
        self._client.close()

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _rid(state: dict[str, Any], out: TickOutput) -> str:
        """Recover the fleet robot id for a state's extras entry.

        The VDA serial is sanitized (AMR_07); extras are keyed by the raw
        fleet id (AMR-07). Serial with '_' -> '-' restores the raw id.
        """
        raw = state["serialNumber"].replace("_", "-")
        return raw if raw in out.extras else state["serialNumber"]

    def _post(self, table: str, rows: list[dict[str, Any]],
              on_conflict: str, merge: bool) -> None:
        """Bulk upsert (merge=True) or insert-if-absent (merge=False)."""
        resolution = "merge-duplicates" if merge else "ignore-duplicates"
        try:
            resp = self._client.post(
                f"{self.rest}/{table}",
                params={"on_conflict": on_conflict},
                json=rows,
                headers={
                    **self._headers(),
                    "Prefer": f"resolution={resolution}, return=minimal",
                },
            )
            if resp.status_code >= 400:
                log.warning("supabase %s POST -> %s: %s",
                            table, resp.status_code, resp.text[:200])
        except httpx.HTTPError as exc:
            # A dropped tick is fine for telemetry; next tick overwrites.
            log.warning("supabase %s POST failed: %s", table, exc)
