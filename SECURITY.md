# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead:
**Security tab → "Report a vulnerability"** on this repository.
Include what you found, how to reproduce it, and the impact you expect.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 3 working days |
| Triage and severity (CVSS v3.1/v4) | 7 days |
| Fix or mitigation for High/Critical | 30 days |
| Public advisory + CVE (via GitHub) | on release of the fix |

Please allow up to 90 days before public disclosure; we will tell you if we
need longer and why. Reporters are credited in the advisory unless they ask
not to be. **Safe harbour:** good-faith research against *your own* deployment
or the documented loopback/demo stack, without exfiltrating data, degrading
service, or touching other people's workspaces, will not be pursued legally.
Do not test against the hosted demo project at volume.

## Supported versions

Security fixes go to the latest released minor version (`v0.x` while the
project is pre-1.0) and to `main`. Older minors are not patched; upgrade.

## Classes of issue we treat as vulnerabilities

Authentication/authorisation bypass (RLS, RBAC, the sandbox door, ingest keys),
injection and XSS in the console, **server-side request forgery** (every
admin-editable outbound target goes through `yantracore.netguard`), secret
exposure, command-gate bypass (a robot-affecting action that skips the
`commands` approval), and supply-chain weaknesses in CI or the install scripts.

## Scope

In scope: everything in this repository (console, academy, copilot,
ops/sandbox door, notifier, connector, simulator, SQL migrations, deploy
kits, CI).

Out of scope: findings that need a leaked service_role key or a database
password (those are operator-held secrets, see below), volumetric DoS, and
issues in third-party services (Supabase, Twilio, LLM providers).

## What is, and is not, a secret in this repo

| Value | Secret? | Notes |
|---|---|---|
| Supabase **publishable / anon** key (`sb_publishable_…`) | No | Designed to ship in browsers. Its power is whatever Row Level Security allows. |
| Supabase **service_role** key (`sb_secret_…`) | **Yes** | Bypasses RLS. Servers and cron only. Never in a browser, in git, or in a URL. |
| Database password / `--db-url` | **Yes** | Used by `yantraops migrate`. Never commit it. |
| `SARATHI_TOKEN`, `YANTRA_WEBHOOK_SECRET`, `GEMINI_API_KEY`, Twilio credentials | **Yes** | Env file (`chmod 600`) or the admin settings panel. |
| Workspace ingest keys (`yk_…`) | **Yes** | Per-workspace bearer secret; hashed at rest, shown once, revocable. |

If you **fork** this repository: no component has a built-in backend any more;
each exits with an error until you set **your own** project
(`SUPABASE_URL` / `SUPABASE_KEY`). The maintainers' public demo project is used
only if you set `YANTRA_ALLOW_DEMO_BACKEND=1`. Read
[`docs/SECURITY.md`](docs/SECURITY.md) for the demo / hardened / RBAC modes.
Never commit a `.env` file; `.gitignore` and the CI secret scan are there to
catch mistakes, not to excuse them.

## If a secret leaks

1. **Rotate it first** (Supabase dashboard → Settings → API; or the admin
   settings panel for app secrets). Removing it from git history does not
   un-leak it.
2. Then clean the history if you want to, and tell us if it was ours.
