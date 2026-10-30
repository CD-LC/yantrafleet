<p align="center">
  <a href="https://yantrika.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="marketing/assets/brand/logo-horizontal-dark.svg">
      <img src="marketing/assets/brand/logo-horizontal-light.svg" alt="Yantrika — AMR fleet management" width="320">
    </picture>
  </a>
</p>

<p align="center">
  <a href="https://github.com/CD-LC/yantrafleet/actions/workflows/ci.yml"><img src="https://github.com/CD-LC/yantrafleet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2563c9" alt="License: MIT"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-2563c9" alt="Security policy"></a>
  <a href="docs/SECURITY.md#outbound-requests-and-ssrf"><img src="https://img.shields.io/badge/SSRF-guarded-2ea44f" alt="SSRF-guarded outbound requests"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/CD-LC/yantrafleet"><img src="https://api.scorecard.dev/projects/github.com/CD-LC/yantrafleet/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-3776ab" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/VDA%205050-v2.1-2563c9" alt="VDA 5050 v2.1">
</p>

# Yantrika

**v0.13.0** · 11 test suites, 700+ tests, all green · MIT license · hosted at [yantrika.ai](https://yantrika.ai)

An end-to-end fleet-operations platform for multi-vendor AMR (autonomous
mobile robot) fleets — the operations layer for Physical AI. Robots (or the
bundled simulator) speak VDA 5050 v2.1 over MQTT; a connector translates that
into a shared Supabase schema; on top sit a live web console with a human
approval gate, automatic incidents, predictive maintenance, real alert
delivery, and an AI copilot grounded in your fleet's actual data.

**Two ways to use it, one codebase:**

| | |
|---|---|
| **Yantrika Cloud** (hosted, free while in beta) | [See the demo — no login](https://yantrika.ai/console/#demo) · [Create a free workspace](https://yantrika.ai/console/#signup) · [Start a throwaway live sandbox](https://yantrika.ai/#demo-live). Signing up provisions a private workspace (your own `site_id`, admin role, ingest keys to connect robots over VDA 5050 or REST, a one-click simulated fleet, role-scoped seats for your team). Contract: [docs/WORKSPACES.md](docs/WORKSPACES.md). |
| **Self-hosted** (MIT, forever) | The quickstart below runs the whole platform on your laptop with no cloud account; `deploy/` has scripted AWS and Azure kits; `supabase/0019_workspaces.sql` turns self-serve workspaces on for your own deployment. |

## Quickstart — 3 commands, zero config

```bash
git clone <this repo> && cd yantrafleet
./install.sh                                  # Windows: powershell -ExecutionPolicy Bypass -File install.ps1
.venv/bin/python -m yantraops up --loopback   # Windows: .venv\Scripts\python.exe -m yantraops up --loopback
```

Open the console URL from the `READY` banner (it auto-opens your browser).
That is the FULL platform — simulated fleet, auto-incidents, predictive
maintenance, notifier, Sarathi copilot — against an embedded in-memory
backend. No cloud, no keys, no robots.

**Docs:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (what we built and how
— the comprehensive reference) · [docs/index.html](docs/index.html)
(overview, architecture, FAQ) ·
[docs/RUNBOOK-WINDOWS.md](docs/RUNBOOK-WINDOWS.md) (PowerShell runbook) ·
[deploy/aws/](deploy/aws/README.md) (run it on EC2) ·
[docs/SECURITY.md](docs/SECURITY.md) (security posture & hardening) ·
[docs/COMPLIANCE.md](docs/COMPLIANCE.md) (SOC2/ISO/EU AI Act/VDA5050 mapping)

All components share one Supabase (PostgREST) backend and one `robots`
row shape:

```
robots(id, vendor, status, battery, pos jsonb [x,y], speed, task_kind,
       health, motor_temp, tasks_done, fault_msg, updated_at)
alerts(id, sev, msg, src, tlabel, ack, created_at)
fleet_meta(id=1, writer_id, sim_min, throughput, updated_at)
robot_telemetry(id, robot_id, ts, battery, speed, motor_temp, status, pos)
incidents(id, sev, title, src, tlabel, state, impact, rca, fix, dur,
          created_at)  — written by the detector, read/patched by console
                         and copilot (rca/fix nullable)
commands(id, robot_id, cmd, status, requested_by, decided_by, ..., note)
missions(id, name, robots jsonb, state, prog, eta, created_at)
          — upserted by the simulator's rolling mission pool, read by console
maintenance_findings(id, robot_id, component, finding, rul_days, confidence,
          action, state, created_at, cleared_at)
          — written by the detector's --maintenance mode, read by console
```

## Components

| Directory    | Package       | What it does |
|--------------|---------------|--------------|
| `sim/`       | `yantrasim`   | Deterministic 10-AMR warehouse simulator (3 vendors, 8x5 waypoint grid, chargers, faults). Emits VDA 5050 v2.1 `state` messages; publishes to Supabase (default), MQTT (`[mqtt]` extra), or stdout. |
| `connector/` | `yantrabridge`| Pure VDA 5050 v2.1 → Supabase row translation, alert dedup (inactive→active edges, battery hysteresis), and a batched PostgREST sink. Sources: JSONL file or MQTT. |
| `copilot/`   | `sarathi`     | FastAPI service (`POST /ask` on :8001) that answers fleet questions with cited evidence. Degrades through tiers: `grounded` (LLM + live tools) → `llm_only` → `offline` (template answers, no LLM needed). |
| `console/`   | —             | Single-file web console (`index.html`, no build step): live map, robot detail, alerts, incidents (with recorded-telemetry replay), and a Copilot panel that calls sarathi first and falls back to a local rule engine. |
| `detector/`  | `yantradetect`| Incident detector: polls `robots`, maintains `incidents` — PagerDuty-style dedup with deterministic idempotent `INC-XXXX` ids, Prometheus-style pending window + clear hold, re-open window with flap counting, stale auto-resolve. `python -m yantradetect --interval 5` (or `--once`, `--dry-run`). With `--maintenance` it instead reads `robot_telemetry` windows and maintains `maintenance_findings` (predictive trends, see v0.5 below). |
| `notifier/`  | `yantranotify`| Notification fan-out: polls unacked `crit`/`serious` alerts and `Open` incidents, dedups per event, and pushes through console / webhook (`WEBHOOK_URL`) / WhatsApp (Twilio env vars) channels. `python -m yantranotify --interval 10` (or `--once`, `--dry-run`, `--state-file`). |
| `e2e/`       | —             | Offline end-to-end suite: `fakerest.py` (in-process fake PostgREST on 127.0.0.1) + `test_e2e.py` driving sim transport → command gate → copilot toolbox → detector sink over real localhost HTTP, zero network egress. |
| `core/`      | `yantracore`  | Canonical status contract shared by every component (`active · idle · charging · paused · estop · degraded · fault`) plus the multi-site `site_id()` helper. Enforced by a DB CHECK constraint. |
| `ops/`       | `yantraops`   | One-command orchestrator: `up --loopback` (zero-config demo) / `--supabase` / `--mqtt`, `migrate --db-url` (tracked, checksummed schema apply), `doctor` (environment preflight), `status`. |
| `supabase/`  | —             | Ordered, idempotent SQL migrations `0001`–`0005` (schema for every table above) + where to find your `--db-url`. |
| `docker/`    | —             | Container packaging for the demo stack (host networking; Linux/CI). |
| `deploy/`    | —             | Cloud deployment guides — currently `deploy/aws/` for a single-EC2 demo. |
| `docs/`      | —             | Project docs: landing page (`index.html`), Windows runbook, security notes. |

## Install

Prefer manual control? Any OS, in a venv of your choosing:

```bash
pip install -e core -e sim -e connector -e detector -e notifier -e ops
pip install -r copilot/requirements.txt
python -m yantraops up --loopback
```

Add `--supabase` (after applying the migrations in `supabase/`) to run
against your real project; `python -m yantraops status` health-checks a
running stack. **Deploying for real, not just evaluating?** The baseline
migrations leave the project demo-open (anyone with the anon key can
read/write everything) — see `supabase/README.md`'s "Going to
production" section for the one-command path to RBAC
(`migrate --include-opt-in` + `grant-role`).

The one-shot installers create a `.venv` in the repo root, install the six
Python packages editable plus the copilot requirements, and print the exact
command to start the demo. Both are idempotent — re-run them any time to
refresh an install. Python 3.10+ is required (the scripts find one for you
or tell you where to get it).

```bash
# Linux/macOS
./install.sh            # install only
./install.sh --run      # install, then start the loopback demo
```

```powershell
# Windows (PowerShell 5.1+; no venv activation needed)
powershell -ExecutionPolicy Bypass -File install.ps1        # install only
powershell -ExecutionPolicy Bypass -File install.ps1 -Run   # install + start
```

Afterwards, start the demo any time with:

```bash
.venv/bin/python -m yantraops up --loopback          # Linux/macOS
```
```bat
.venv\Scripts\python.exe -m yantraops up --loopback  :: Windows
```

## Docker

```bash
docker build -f docker/Dockerfile -t yantrafleet .
docker run --rm --init --network host yantrafleet     # Linux
```

or `docker compose -f docker/docker-compose.yml up --build`. Open the
console URL from the `✔ READY` line. The stack binds 127.0.0.1 on ephemeral
ports, so `-p` port publishing cannot reach it — host networking is the
supported path (Linux; Docker Desktop needs its host-networking option).
Details, headless/CI usage, and the macOS/Windows story: `docker/README.md`.

## Manual quickstart (Windows)

Prereqs: Python 3.11+, a modern browser. From the repo root:

```bat
:: 1) install
pip install -e core -e sim -e connector -e detector -e notifier
pip install -r copilot\requirements.txt

:: 2) start the simulator (writes robots/alerts/fleet_meta/telemetry/missions)
py -m yantrasim --supabase

:: 2b) start the incident detector (optional; maintains the incidents table)
py -m yantradetect --interval 5

:: 2c) predictive maintenance pass (optional; maintains maintenance_findings)
py -m yantradetect --maintenance --interval 60

:: 2d) start the notifier (optional; pushes crit/serious alerts + open incidents)
py -m yantranotify --interval 10

:: 3) start the copilot service (new terminal, from copilot\)
py -m uvicorn sarathi.server:app --port 8001

:: 4) open the console
start console\index.html
```

The console auto-elects leader/follower against `fleet_meta.writer_id`; with
the simulator running it follows the simulator's data. The Copilot panel uses
`http://localhost:8001/ask` (4 s timeout) and silently falls back to its
built-in rule engine when sarathi is not running.

Optional:

```bat
:: replay recorded VDA 5050 state through the connector
py -m yantrabridge --file connector\sample.jsonl

:: offline demo without Supabase
py -m yantrasim --stdout --ticks 20
```

Configuration: every component needs `SUPABASE_URL` + `SUPABASE_KEY` for your own
project, or it refuses to start (nothing falls back to the maintainers' project
unless you set `YANTRA_ALLOW_DEMO_BACKEND=1`). `--loopback` needs neither. Copilot LLM tiers activate with
`GEMINI_API_KEY` or `OPENAI_API_KEY` (or `SARATHI_MODEL`); without a key it
serves grounded template answers (`tier: offline`).

## Security

Secure by default; every opt-out is explicit and named.

- **RLS-locked backend.** Anonymous visitors read and write nothing; roles
  (`operator` < `engineer` < `manager` < `admin`) are enforced in Postgres, not
  in the UI. The only anonymous write paths are a throwaway `DEMO-*` sandbox and
  per-workspace ingest keys, each pinned to a single site.
- **SSRF-guarded outbound requests.** Webhook and MQTT targets that an admin can
  edit are resolved and refused if they point at metadata, loopback or private
  ranges (`core/yantracore/netguard.py`, [details](docs/SECURITY.md#outbound-requests-and-ssrf)).
- **Fail-closed configuration.** No silent fallback to someone else's database;
  the copilot needs a token unless you opt in to anonymous access.
- **Hardened front-ends.** Backend-redirect gate for URL overrides, row
  sanitising against stored XSS, CSP/HSTS headers, optional Turnstile CAPTCHA on
  sign-up.
- **Supply chain.** Secret scan over the tree and full history in CI, dependency
  audit, CodeQL, OpenSSF Scorecard, Dependabot, least-privilege CI tokens.

Found a vulnerability? See [SECURITY.md](SECURITY.md) (private reporting).
Hardening a fork or going live: [docs/SECURITY.md](docs/SECURITY.md).

## Tests

Each Python component has an offline pytest suite (no network, no browser):

```bat
cd core & py -m pytest
cd sim & py -m pytest
cd connector & py -m pytest
cd copilot & py -m pytest
cd detector & py -m pytest
cd notifier & py -m pytest
cd console & py -m pytest   :: needs Node for the inline-script syntax check
cd e2e & py -m pytest       :: offline end-to-end (fake PostgREST loopback)
```

Run each suite from its own directory (test module basenames collide across
components). See `TEST-REPORT.md` for the latest verification run.

## v0.5 — missions, predictive maintenance, notifier & MCP

Apply `supabase/0004_maintenance.sql` (after 0001–0003). Then:

1. **Missions** — the simulator keeps up to 3 concurrent missions in flight
   (2–4 robots each, 10–20 planned tasks; deterministic rolling names like
   "Outbound wave #1" / "Cycle count — Storage A" / "Inbound putaway —
   Dock 1"). Robots' completed tasks credit their mission; state runs
   `Queued → Running → Done` with an integer `prog` percent and a clock
   ETA. Every tick the snapshot is upserted into `missions`
   (`on_conflict=id`) so writes are idempotent; the console's Missions view
   pulls the table live (~6 s) and can insert new missions.
2. **Predictive maintenance** — `py -m yantradetect --maintenance
   [--window-hours 6]` reads recent `robot_telemetry` and maintains
   `maintenance_findings`: motor-temp trend ≥1.5 °C/hr (r²≥0.5) → *drive
   motor*; battery drain ≥1.5× fleet median per active-minute → *battery*;
   active-speed decline ≥15% across the window → *drivetrain*. Each row
   carries a human-readable `finding`, heuristic `rul_days`, `confidence`
   (0–1), and a recommended `action`; at most one Open finding per
   robot+component, cleared (never deleted) when the trend abates.
3. **Notifier** — `py -m yantranotify --interval 10` polls unacked
   `crit`/`serious` alerts and `Open` incidents, dedups, and fans out to
   console / webhook / WhatsApp channels. Channels without credentials
   print the payload instead of sending, so it runs safely with no secrets.
4. **MCP server** — `py -m sarathi.mcp_server` (from `copilot\`) exposes
   the same evidence-grounded Toolbox over the Model Context Protocol
   (stdio) for external agents such as Claude Desktop: `fleet_summary`,
   `query_robots`, `query_alerts`, `query_incidents`, `query_commands`,
   `robot_history` — each returning full JSON with a `source_id` citation
   key. Setup details: `copilot/README-MCP.md`.

## v0.4 — incident detector, real replay & e2e

Apply `supabase/0003_telemetry.sql` if you have not already (v0.3 schema).
Then:

1. **Detector** — `py -m yantradetect --interval 5` polls `robots` and
   opens/resolves `incidents` rows: a robot seen in `fault`/`estop` for 2
   consecutive polls opens an incident (`sev` crit/serious); recovery
   resolves it with duration and impact. Deterministic ids make retried
   writes idempotent; `--dry-run` prints actions without writing.
2. **Incident replay from recorded telemetry** — opening an incident in the
   console fetches the robot's `robot_telemetry` rows in a window around the
   incident's `created_at` and drives the replay map, scrubber, and
   battery/speed charts from real samples (alerts in the window become event
   dots). With fewer than 10 recorded samples the scripted INC-1042 demo
   replay is shown instead, with a note.
3. **Copilot telemetry** — ask sarathi about a robot's recent telemetry; the
   `query_telemetry` tool returns windowed samples plus battery/speed/
   motor-temp stats and status-transition counts.

## v0.2 — command gate & canonical statuses

Apply `supabase/0002_commands.sql` in the Supabase SQL Editor (after the v0.1
schema). Then:

1. In the console, robot actions (pause / send-to-charge / e-stop) no longer
   act directly when a live backend is connected — they queue as `pending`
   rows in the `commands` table.
2. The **Pending approvals** card on Overview lets an operator approve or
   reject each command (full audit: who asked, who decided, when, outcome).
3. A running `py -m yantrasim --supabase` polls approved commands, executes
   them in the world, and marks them `executed`/`failed` with a reason.
4. Robot statuses everywhere use one vocabulary (`core/yantracore`):
   `active · idle · charging · paused · estop · degraded · fault` — enforced
   by a DB CHECK constraint.

A live `yantrasim` feed outranks console tabs: consoles automatically become
viewers while the simulator (or a future robot adapter) is publishing.
