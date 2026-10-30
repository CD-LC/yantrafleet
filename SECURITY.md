# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead:
**Security tab → "Report a vulnerability"** on this repository.
Include what you found, how to reproduce it, and the impact you expect.

You can expect an acknowledgement within a few days. Please give us a
reasonable window to ship a fix before disclosing publicly.

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

If you **fork** this repository: the embedded default Supabase project is the
maintainers' demo backend. Point your fork at **your own** project
(`SUPABASE_URL` / `SUPABASE_KEY`) before putting real data anywhere, and read
[`docs/SECURITY.md`](docs/SECURITY.md) for the demo / hardened / RBAC modes.
Never commit a `.env` file; `.gitignore` and the CI secret scan are there to
catch mistakes, not to excuse them.

## If a secret leaks

1. **Rotate it first** (Supabase dashboard → Settings → API; or the admin
   settings panel for app secrets). Removing it from git history does not
   un-leak it.
2. Then clean the history if you want to, and tell us if it was ours.
