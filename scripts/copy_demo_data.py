#!/usr/bin/env python3
"""Copy fleet history from one Supabase project to another.

    # 1) look first (changes nothing):
    export YF_TARGET_URL=https://<new-ref>.supabase.co
    export YF_TARGET_SERVICE_KEY=...        # the NEW project's service_role key
    python scripts/copy_demo_data.py --source-url https://<old-ref>.supabase.co \\
                                     --source-key sb_publishable_...

    # 2) then do it:
    python scripts/copy_demo_data.py ... --apply

The target key is read from the ENVIRONMENT, never from argv, so it does not
land in shell history or a process listing - and it must be a service_role key:
a locked-down project refuses writes from the publishable key by design, and
this script refuses to try with one.

What it will NOT copy, on purpose
* ``commands`` - an approved row is an instruction a robot executor will act on;
  history of what strangers once queued must never become live again.
* ``fleet_meta`` - a writer heartbeat, meaningless elsewhere.
* any row with markup / script-ish characters in a text field. The old project
  was demo-open, so its rows were writable by anyone; those are skipped and
  counted rather than trusted.

Re-running is safe for every table except ``robot_telemetry``: its id is
``generated always``, so rows go in without one and a second run would duplicate
them. The script therefore refuses to touch telemetry if the target already has
any (override with --append-telemetry if you really mean it).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

#: copy order; (table, conflict column or None for plain insert)
TABLES = [
    ("robots", "id"),
    ("alerts", "id"),
    ("incidents", "id"),
    ("missions", "id"),
    ("robot_telemetry", None),
]
PAGE = 1000          # PostgREST's default max rows per response
BATCH = 500
# Anything that can open a tag, close an attribute or break a JS string.
UNSAFE = re.compile(r"[<>`\\]|&#|javascript:|\bon\w+\s*=|['\"]\s*[);]", re.I)


def is_privileged_key(key: str) -> bool:
    """True only for a service_role key. Publishable / anon keys are refused."""
    if not key or key.startswith("sb_publishable_"):
        return False
    if key.startswith("sb_secret_"):
        return True
    parts = key.split(".")
    if len(parts) == 3:
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(payload)).get("role") == "service_role"
        except Exception:
            return False
    return False


def row_is_safe(row: dict) -> bool:
    def walk(v) -> bool:
        if isinstance(v, str):
            return not UNSAFE.search(v)
        if isinstance(v, list):
            return all(walk(x) for x in v)
        if isinstance(v, dict):
            return all(walk(x) for x in v.values())
        return True
    return walk(row)


def _call(url: str, key: str, method="GET", body=None, headers=None):
    h = {"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=h)  # noqa: S310 (operator-supplied URL)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
            raw = r.read()
            return r.status, dict(r.headers), (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")[:300]


def read_all(base: str, key: str, table: str):
    offset = 0
    while True:
        q = urllib.parse.urlencode({"select": "*", "order": "id.asc", "limit": PAGE, "offset": offset})
        status, _, rows = _call(f"{base}/rest/v1/{table}?{q}", key)
        if status != 200:
            raise SystemExit(f"read {table} failed: HTTP {status} {rows}")
        if not rows:
            return
        yield from rows
        if len(rows) < PAGE:
            return
        offset += PAGE


def count_rows(base: str, key: str, table: str) -> int:
    status, hdr, _ = _call(f"{base}/rest/v1/{table}?select=id&limit=1", key,
                           headers={"Prefer": "count=exact"})
    if status not in (200, 206):
        raise SystemExit(f"count {table} failed: HTTP {status}")
    cr = {k.lower(): v for k, v in hdr.items()}.get("content-range", "*/0")
    return int(cr.split("/")[-1] or 0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--source-key", required=True, help="publishable key of the SOURCE project")
    ap.add_argument("--apply", action="store_true", help="actually write (default: dry run)")
    ap.add_argument("--append-telemetry", action="store_true",
                    help="copy telemetry even if the target already has some (duplicates!)")
    args = ap.parse_args(argv)

    src = args.source_url.rstrip("/")
    dst = (os.environ.get("YF_TARGET_URL") or "").rstrip("/")
    key = os.environ.get("YF_TARGET_SERVICE_KEY") or ""
    if not dst:
        return print("set YF_TARGET_URL to the NEW project's URL") or 2
    if dst == src:
        return print("source and target are the same project") or 2
    if not is_privileged_key(key):
        return print("YF_TARGET_SERVICE_KEY must be the new project's service_role key "
                     "(a publishable/anon key cannot write to a locked-down project)") or 2

    print(f"{'APPLY' if args.apply else 'DRY RUN'}: {src}  ->  {dst}\n")
    total_in = total_skip = 0
    for table, conflict in TABLES:
        if table == "robot_telemetry" and not args.append_telemetry:
            have = count_rows(dst, key, table)
            if have:
                print(f"{table:18s} SKIPPED - target already has {have} rows (would duplicate); "
                      f"use --append-telemetry to force")
                continue
        ok, skipped, buf = 0, 0, []

        def flush(table=table, conflict=conflict):
            nonlocal ok, buf
            if not buf:
                return
            url = f"{dst}/rest/v1/{table}" + (f"?on_conflict={conflict}" if conflict else "")
            prefer = "return=minimal" + (",resolution=merge-duplicates" if conflict else "")
            status, _, body = _call(url, key, "POST", buf, {"Prefer": prefer})
            if status not in (200, 201, 204):
                raise SystemExit(f"write {table} failed: HTTP {status} {body}")
            ok += len(buf)
            buf = []

        for row in read_all(src, args.source_key, table):
            if not row_is_safe(row):
                skipped += 1
                continue
            if conflict is None:
                row = {k: v for k, v in row.items() if k != "id"}   # generated always
            if args.apply:
                buf.append(row)
                if len(buf) >= BATCH:
                    flush()
            else:
                ok += 1
        if args.apply:
            flush()
        total_in += ok
        total_skip += skipped
        print(f"{table:18s} {'copied' if args.apply else 'would copy'} {ok:6d}   skipped(unsafe) {skipped}")
    print(f"\n{'copied' if args.apply else 'would copy'} {total_in} rows, skipped {total_skip} unsafe.")
    if not args.apply:
        print("dry run only - add --apply to write.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
