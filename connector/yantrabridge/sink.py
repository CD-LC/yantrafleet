"""Supabase (PostgREST) sink for translated rows.

Writes go through ``httpx``; the transport is injectable so unit tests run
fully offline with ``httpx.MockTransport``. Batch upserts follow the
PostgREST rules: ``on_conflict=<pk>`` + ``Prefer: resolution=merge-duplicates``
for robots / fleet_meta, and ``resolution=ignore-duplicates`` for alerts so
retries are idempotent (alert ids are deterministic per occurrence).

Because PostgREST requires every row in one batch to carry identical keys,
rows are grouped by key-set before sending.

Workspace mode (supabase/0019, docs/WORKSPACES.md): with an INGEST KEY
(``ingest_key=`` / ``--ingest-key`` / ``YANTRA_INGEST_KEY``) the sink
writes as a self-serve workspace's own connector — the anon key plus
``x-yf-ingest-key`` on every request, resolved by 0019's RLS to exactly
one ``WS-*`` site. The site MUST be that workspace (``WS-<8 hex>``, from
``site=`` / ``--site`` / ``YANTRA_SITE_ID``; anything else refuses to
construct), every robot / alert / telemetry id is prefixed ``<site>-``
because ``robots.id`` is a global primary key shared by every tenant,
and :meth:`SupabaseSink.heartbeat` becomes a no-op (``fleet_meta`` has no
``site_id``, so a key cannot reach it — logged once at INFO).
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable

import httpx

log = logging.getLogger(__name__)

# Client-safe publishable anon key — fine to embed; override via env vars.
from yantracore.backend import DEMO_KEY as DEFAULT_SUPABASE_KEY  # noqa: E402,F401  (re-export; opt-in only)
from yantracore.backend import DEMO_URL as DEFAULT_SUPABASE_URL  # noqa: E402,F401
from yantracore.backend import resolve_backend  # noqa: E402,F401

#: 0019 ingest-key contract (public.yf_ingest_key / yf_is_workspace_site).
#: Duplicated here rather than imported: the connector is a standalone
#: package a customer runs next to their robots with nothing else installed.
INGEST_KEY_HEADER = "x-yf-ingest-key"
INGEST_KEY_ENV = "YANTRA_INGEST_KEY"
INGEST_KEY_RE = re.compile(r"^yk_[0-9a-f]{64}$")
WS_SITE_RE = re.compile(r"^WS-[0-9a-f]{8}$")


def resolve_ingest_key(key: str | None = None) -> str | None:
    """Explicit arg > ``YANTRA_INGEST_KEY`` > None (no workspace mode)."""
    return (key or os.environ.get(INGEST_KEY_ENV) or "").strip() or None


def check_ingest_config(key: str | None, site: str | None) -> None:
    """Refuse to start with a key that cannot work.

    A malformed key is plain anon to 0019's RLS (every write 401s), and a
    key paired with a non-workspace site stamps rows the policy refuses
    (``site_id = yf_ingest_site()`` can only ever be the key's own ``WS-*``
    site). Both are configuration mistakes worth a loud exit at startup.
    """
    if key is None:
        return
    if not INGEST_KEY_RE.match(key):
        raise ValueError(
            "ingest key is malformed — expected 'yk_' followed by 64 lowercase "
            "hex characters, as workspace_create_ingest_key() returns it")
    if not site or not WS_SITE_RE.match(site):
        raise ValueError(
            f"an ingest key writes exactly one self-serve workspace, and "
            f"{site!r} is not one — pass --site WS-<8 hex> (or set "
            "YANTRA_SITE_ID) to the workspace the key was created in (see "
            "docs/WORKSPACES.md)")


def namespace_rows(table: str, rows: list[dict[str, Any]],
                   site: str) -> list[dict[str, Any]]:
    """Prefix every id a workspace writer emits with ``<site>-``.

    ``robots.id`` and ``alerts.id`` are global text primary keys shared by
    every tenant of one project, so two workspaces that both own an
    ``AGV-001`` must not collide. The console strips the prefix for
    display. References are rewritten consistently (telemetry and alert
    ``src`` point at the prefixed robot id) and ``site_id`` is forced to
    the workspace — the policy would refuse anything else anyway.
    """
    prefix = f"{site}-"

    def pre(value: Any) -> Any:
        if isinstance(value, str) and value and not value.startswith(prefix):
            return prefix + value
        return value

    out = []
    for row in rows:
        r = dict(row)
        if table in ("robots", "alerts") and "id" in r:
            r["id"] = pre(r["id"])
        if table == "robot_telemetry":
            r["robot_id"] = pre(r.get("robot_id"))
        if table == "alerts" and r.get("src") not in (None, "", "fleet"):
            r["src"] = pre(r["src"])
        r["site_id"] = site
        out.append(r)
    return out


def strip_namespace(robot_id: str, site: str) -> str:
    """The inverse of :func:`namespace_rows` for an id read back."""
    prefix = f"{site}-"
    return robot_id[len(prefix):] if robot_id.startswith(prefix) else robot_id


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _group_by_keyset(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split rows into batches whose dicts share the exact same key set."""
    groups: dict[frozenset[str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(frozenset(row.keys()), []).append(row)
    return list(groups.values())


class SupabaseSink:
    """Thin PostgREST writer for the Yantrika tables.

    Parameters
    ----------
    url, key:
        Supabase project URL and anon key. Defaults come from the
        ``SUPABASE_URL`` / ``SUPABASE_KEY`` env vars, then the embedded
        project defaults.
    transport:
        Optional ``httpx.BaseTransport`` (e.g. ``httpx.MockTransport``) for
        offline testing.
    writer_id:
        Identifier written to ``fleet_meta.writer_id`` on heartbeat.
    ingest_key, site:
        Workspace mode (see the module docstring). ``ingest_key`` falls
        back to ``YANTRA_INGEST_KEY``; ``site`` to ``YANTRA_SITE_ID``. A key
        with a non-``WS-*`` site raises :class:`ValueError` here, at
        construction, so the failure is one line at startup.
    """

    def __init__(
        self,
        url: str | None = None,
        key: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        writer_id: str = "yantrabridge",
        timeout: float = 10.0,
        ingest_key: str | None = None,
        site: str | None = None,
    ) -> None:
        self.url, self.key = resolve_backend(url, key)
        self.writer_id = writer_id
        self.ingest_key = resolve_ingest_key(ingest_key)
        self.site = (site or os.environ.get("YANTRA_SITE_ID") or "").strip() or None
        check_ingest_config(self.ingest_key, self.site)
        self._logged_heartbeat_skip = False
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        if self.ingest_key:
            headers[INGEST_KEY_HEADER] = self.ingest_key
            log.info("workspace mode: writing site %s with an ingest key — "
                     "ids namespaced '%s-', fleet_meta skipped", self.site,
                     self.site)
        self._client = httpx.Client(
            base_url=f"{self.url}/rest/v1",
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    def _shape(self, table: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Workspace namespacing when a key is configured, else untouched."""
        if not self.ingest_key:
            return rows
        assert self.site is not None  # check_ingest_config guarantees it
        return namespace_rows(table, rows, self.site)

    # -- low-level ----------------------------------------------------------

    def _post(
        self,
        table: str,
        rows: list[dict[str, Any]],
        *,
        on_conflict: str,
        resolution: str,
    ) -> None:
        """One PostgREST bulk write; raises on HTTP error."""
        resp = self._client.post(
            f"/{table}",
            params={"on_conflict": on_conflict},
            json=rows,
            headers={"Prefer": f"resolution={resolution}, return=minimal"},
        )
        resp.raise_for_status()

    # -- table writers ------------------------------------------------------

    def upsert_robots(self, rows: Iterable[dict[str, Any]]) -> int:
        """Upsert robot rows (merge on id). Returns rows sent."""
        rows = self._shape("robots", list(rows))
        for batch in _group_by_keyset(rows):
            self._post("robots", batch, on_conflict="id", resolution="merge-duplicates")
        return len(rows)

    def insert_alerts(self, rows: Iterable[dict[str, Any]]) -> int:
        """Insert alert rows; duplicates (same id) are ignored -> retry-safe."""
        rows = self._shape("alerts", list(rows))
        if rows:
            for batch in _group_by_keyset(rows):
                self._post("alerts", batch, on_conflict="id",
                           resolution="ignore-duplicates")
        return len(rows)

    def insert_telemetry(
        self, rows: Iterable[dict[str, Any]], *, chunk_size: int = 500
    ) -> int:
        """Bulk-insert ``robot_telemetry`` history rows. Returns rows sent.

        The table's primary key is a generated identity, so this is a plain
        insert (no on_conflict); rows are chunked to keep request bodies
        small on large imports.
        """
        rows = self._shape("robot_telemetry", list(rows))
        for group in _group_by_keyset(rows):
            for i in range(0, len(group), chunk_size):
                resp = self._client.post(
                    "/robot_telemetry",
                    json=group[i:i + chunk_size],
                    headers={"Prefer": "return=minimal"},
                )
                resp.raise_for_status()
        return len(rows)

    def heartbeat(self) -> None:
        """Upsert fleet_meta row 1 with our writer id + timestamp.

        Only touches writer_id/updated_at, so sim_min/throughput written by
        other writers are preserved (PostgREST updates only supplied columns).

        In workspace mode this is a no-op: ``fleet_meta`` has no ``site_id``,
        so 0019 keeps it off-limits to an ingest key and there is nothing to
        scope a heartbeat by. Said once, at INFO, not once per batch.
        """
        if self.ingest_key:
            if not self._logged_heartbeat_skip:
                self._logged_heartbeat_skip = True
                log.info("workspace mode: fleet_meta heartbeat skipped (the "
                         "table has no site_id; an ingest key cannot write it)")
            return
        self._post(
            "fleet_meta",
            [{"id": 1, "writer_id": self.writer_id, "updated_at": _now_iso()}],
            on_conflict="id",
            resolution="merge-duplicates",
        )

    # -- convenience --------------------------------------------------------

    def push(
        self,
        robots: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
        *,
        heartbeat: bool = True,
    ) -> dict[str, int]:
        """Write one translated batch. Returns counts for logging."""
        n_robots = self.upsert_robots(robots) if robots else 0
        n_alerts = self.insert_alerts(alerts) if alerts else 0
        if heartbeat:
            self.heartbeat()
        return {"robots": n_robots, "alerts": n_alerts}

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SupabaseSink":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
