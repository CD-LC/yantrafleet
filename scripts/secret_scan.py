#!/usr/bin/env python3
"""Fail if a real credential is about to be (or already was) committed.

    python scripts/secret_scan.py              # every tracked file
    python scripts/secret_scan.py --history    # every line ever added, all branches

Stdlib only, so CI runs it with no third-party action. It looks for the
classes of secret this project actually handles - Supabase service_role keys
(legacy JWT and ``sb_secret_``), private keys, cloud/LLM/VCS tokens, and
database URLs with a password in them.

The Supabase *publishable* / anon key is NOT a finding: it is meant to ship in
browsers (docs/SECURITY.md). A legacy anon JWT is told apart from a
service_role one by decoding its ``role`` claim.

Add ``secret-scan: allow`` on a line to waive it (test fixtures, docs).
Exit status: 0 clean, 1 findings.
"""
from __future__ import annotations

import base64
import json
import re
import subprocess
import sys

ALLOW_MARK = "secret-scan: allow"

PATTERNS = {
    "supabase secret key": re.compile(r"sb_secret_[A-Za-z0-9_-]{20,}"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Anthropic API key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI-style API key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Twilio API key sid": re.compile(r"\bSK[0-9a-f]{32}\b"),
}
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}")
# scheme://user:password@host  - skipped when the "password" is obviously a placeholder
DB_URL = re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^:/\s@\"']+:([^@\s\"'/]+)@[^\s\"']+")
PLACEHOLDER = re.compile(r"^(?:<.*>|\$\{?.*|%.*|\{.*\}|\*+|x+|\.\.\.|pass(?:word)?|secret|changeme|your.*|example.*|password\d*|pw|db.?pass.*|\[.*\])$", re.I)
SKIP_SUFFIX = (".png", ".webp", ".ico", ".jpg", ".jpeg", ".gif", ".pdf", ".woff", ".woff2")


def _jwt_role(payload_b64: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        return json.loads(raw).get("role")
    except Exception:
        return None


def scan_line(line: str) -> list[str]:
    """Return the kinds of secret found on one line (empty = clean)."""
    if ALLOW_MARK in line:
        return []
    found = [name for name, rx in PATTERNS.items() if rx.search(line)]
    for m in JWT.finditer(line):
        if _jwt_role(m.group(1)) == "service_role":
            found.append("Supabase service_role JWT")
    for m in DB_URL.finditer(line):
        if not PLACEHOLDER.match(m.group(1)):
            found.append("database URL with a password")
    return found


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True,
                          text=True, errors="replace").stdout


def scan_tree() -> list[tuple[str, int, str]]:
    hits = []
    for path in _git("ls-files").splitlines():
        if path.lower().endswith(SKIP_SUFFIX):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    for kind in scan_line(line):
                        hits.append((f"{path}:{n}", kind, line.strip()[:0]))
        except OSError:
            continue
    return hits


def scan_history() -> list[tuple[str, int, str]]:
    hits, commit = [], "?"
    out = _git("log", "--all", "-p", "--no-color", "--format=@@COMMIT %h")
    for line in out.splitlines():
        if line.startswith("@@COMMIT "):
            commit = line.split()[1]
        elif line.startswith("+") and not line.startswith("+++"):
            for kind in scan_line(line[1:]):
                hits.append((f"commit {commit}", kind, ""))
    return hits


def main(argv: list[str]) -> int:
    hits = scan_history() if "--history" in argv else scan_tree()
    for where, kind, _ in hits:
        # Never echo the matched text: the report itself must not leak it.
        print(f"SECRET? {kind} at {where}")
    if hits:
        print(f"\n{len(hits)} finding(s). Rotate the credential FIRST, then remove it "
              f"(or add '{ALLOW_MARK}' if it is a deliberate fixture).")
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
