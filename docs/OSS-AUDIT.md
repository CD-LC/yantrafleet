# Open-source standards audit and the road to "the" VDA 5050 platform

Audited 2026-10-30 against the repository at `main`. Scores are the
auditor's judgement, not a certification; each line says what the score rests
on so you can disagree with it.

**Overall: 8.5 / 10 after the second round of fixes** (6.5 before this audit, 7.5
after the first round). What separates 8.5 from 9 is not code: a first PyPI/GHCR
release actually published, a second maintainer, and the spec-fidelity work in
the VDA 5050 section (official schemas, verified clause numbers, a public
interoperability matrix).

## Scorecard

| Area | Before | Now | Rests on |
|---|---|---|---|
| Security of the code | 7 | 9 | SSRF guard added; RLS/RBAC, command gate, HMAC webhooks, rate limits, secret scan in CI. Console still relies on sanitise-on-read (see S2). |
| CI and supply chain | 6 | 9 | Actions pinned to SHAs, CodeQL, Scorecard, dependency review, pip-audit, least-privilege token. No branch protection, SBOM, signing or provenance. |
| Community and governance | 5 | 7.5 | CoC, governance, support, CODEOWNERS, issue and PR templates, SLA and safe harbour added. One maintainer; Discussions off; no roadmap or "good first issue" labels. |
| Packaging and distribution | 3 | 7 | Nothing is installable with `pip install` or `docker pull`; the README says `git clone`. Biggest gap for adoption. |
| Engineering quality | 7 | 8.5 | 700+ offline tests and a documented test contract are unusually good. No linter, type checker or coverage gate; 5k-line single-file console; one flaky subprocess test in `ops`. |
| VDA 5050 credibility | 6 | 7 | Real 52-check conformance tool, independent from the simulator, zero dependencies. Not yet validated against the official JSON schemas; v2.1 only; no public results. |

## What was wrong, and what was fixed here

### Security

| # | Finding | Severity | Status |
|---|---|---|---|
| S1 | **SSRF.** `WEBHOOK_URL`, the Twilio SID and `CONNECTOR_MQTT_HOST` are editable by a console `admin` (via `app_settings` / `app_config`) and were used for server-side requests with no validation. An admin (or XSS in an admin session) could make the notifier POST to `169.254.169.254`, loopback services or the VPC, and could inject path segments through the SID. | High | **Fixed.** `core/yantracore/netguard.py`: https only, no embedded credentials, every resolved address must be public, metadata/link-local always refused, no redirects, fail-closed DNS, SID percent-encoded; MQTT host refuses metadata but allows LAN. 40+ tests incl. IPv4-mapped, 6to4, multi-record DNS. Opt-in knobs for internal targets. |
| S2 | Console XSS defence was a **sanitiser on the read path** (`Sync.q()`), with ~190 template sites and 47 `innerHTML` uses. One missed path re-opened stored XSS. | High (latent) | **Fixed (defence in depth).** Every `innerHTML` assignment now passes through `YFSafe`: inert parse, dangerous elements dropped, event handlers kept only if they are calls the app itself wires, `javascript:` URLs removed. 57 hostile-payload browser tests (42 fail with the guard off); a static test fails if a new unguarded sink appears. **Still open:** a CSP without `unsafe-inline` needs the inline handlers/script moved out of the single file; the academy page does not use the guard yet. |
| S3 | **Every component defaulted to the maintainer's Supabase project.** A fork that forgot `SUPABASE_URL` sent fleet telemetry to someone else's database. | High (privacy) | **Fixed.** `core/yantracore/backend.py`: URL and key both required, a half configuration is never completed from the demo, and the demo needs `YANTRA_ALLOW_DEMO_BACKEND=1` (loud warning). 12 tests. |
| S4 | Copilot `/ask` was **open unless `SARATHI_TOKEN` was set** and CORS admitted the `null` origin and `*`. | Medium | **Fixed.** `/ask` answers 401 `auth_not_configured` without a token unless `SARATHI_ALLOW_OPEN=1`; CORS is loopback-only unless origins are listed (`null` and `*` only explicitly). `/health` reports `open_access`. Importing `sarathi.app` no longer needs a backend. |
| S5 | DNS-rebinding window between the SSRF check and the connect. | Low | Documented in `netguard.py` and `docs/SECURITY.md`. Close it by connecting to the vetted IP, and add IMDSv2 hop-limit 1 / egress rules at the host. |
| S6 | No supply-chain provenance: no SBOM, no signed releases. | Medium | **Fixed in the workflow, not yet exercised:** `release.yml` builds from a tag, publishes to PyPI by trusted publishing, pushes multi-arch GHCR images, and attaches a CycloneDX SBOM and SLSA attestation. Needs the one-time PyPI trusted-publisher setup and a first tag. Hash-locked requirements are still open. |

### Repository and process

| # | Finding | Status |
|---|---|---|
| R1 | `main` had **no branch protection**. | **Fixed.** Required status checks (secrets, audit, e2e, browser, 7 python jobs), no force-push, no deletion, conversation resolution required. Admins can still bypass, and PR reviews are not required (single maintainer): tighten both when there is a second maintainer. Add `lint` and `python (tools/conformance)` to the required list after their first green run. |
| R2 | Actions used floating tags (`@v4`). | Fixed - pinned to commit SHAs with version comments; Dependabot keeps them current. |
| R3 | The connector CI job never installed `mcap`/`paho-mqtt`, so its import tests errored. | Fixed. |
| R4 | Dependabot covered 3 of 10 Python components. | Fixed. |
| R5 | Missing CoC, governance, support, CODEOWNERS, issue/PR templates, response-time and safe-harbour policy. | Fixed. |
| R6 | GitHub Discussions disabled; no topics set; no GitHub Releases. | Open - repo settings. |
| R7 | `ops` suite has a timing-dependent test (spawns real processes on ephemeral ports) that fails intermittently under load and passed on every isolated rerun. Not yet identified by name. | Open - capture the failing test name in CI and make it event-driven. |
| R8 | No linter / type check / coverage gate. | **Fixed.** `ruff` (pyflakes, bugbear, bandit rules) is clean across the repo; `mypy` is clean and blocking on 6 packages (informational on `copilot` and `ops`, 17 findings); per-component coverage floors; the conformance tool is now in the CI matrix. The lint pass also fixed real defects (`raise` without `from`, unbound loop variables, `sha1` flagged as non-security). A formatter is deliberately not enforced (181 files would reflow). |
| R9 | The academy page (`academy/index.html`, 12 `innerHTML` uses) is outside the console's sink guard, and its `test_webllm` browser test fails on this machine. | Open. |

## The road to "the" VDA 5050 platform

Be honest about what wins here. Nobody picks an operations platform because of
its CI; they pick it because it **demonstrably works with their robots**. The
asset that can be number one is the conformance tester, so build the roadmap
around making its verdict authoritative.

### P0 - credibility of the verdict
1. **Validate against the official VDA 5050 JSON schemas.** The VDA ships
   schemas for order, state, instantActions, connection, factsheet and
   visualization. Use them as the schema layer under the 52 behavioural checks
   (vendor them unmodified with attribution; check the licence terms first).
   Today `state.field_types` hand-codes what the schemas already define.
2. **Verify every clause reference against the published specification.** The
   report prints "VDA 5050 2.1 §6.4" and similar; a single wrong section number
   in a graded report that vendors will dispute undermines all of it. Have a
   second person check the whole table, and add a test that every check has a
   clause and a one-line spec quotation or paraphrase.
3. **Publish a golden corpus**: anonymised real-robot captures (pass and fail)
   in `tools/conformance/corpus/`, with expected results, so any change to a
   check is reviewable against ground truth, not only against the in-repo
   simulator.
4. **Public interoperability matrix.** Run the tool against real vendors'
   simulators/robots (with their consent) and publish the results page. This,
   more than any feature, is what makes the project the reference.

### P1 - adoption
5. **`pip install yantra-conform` and `docker run ghcr.io/.../yantra-conform`.**
   Add a release workflow with PyPI trusted publishing (OIDC, no token), build
   provenance attestations, and a signed multi-arch image. Reserve the PyPI
   names now.
6. **A GitHub Action** (`uses: .../yantra-conform-action`) that runs the tester
   against a broker in CI and fails the build below a grade, so robot vendors
   gate their own releases on it. This is the strongest distribution channel.
7. **Machine-readable output**: JUnit XML and SARIF alongside HTML/JSON, and a
   stable result schema with a version field.
8. Cover the gaps: `visualization`, `factsheet` field-level depth, multi-order
   sequences (horizon/released edges, `orderUpdateId` after a cancel), and
   timing checks (`minStateInterval`, heartbeat), each clause-cited.
9. **Version strategy**: ship a v3.0 rule set behind `--spec 3.0` (the tester
   already refuses a 3.x robot rather than mis-grading it - keep that) and
   document the v2.1 to v3.0 rename table in one place.

### P2 - ecosystem and trust
10. Join the conversation where the standard lives (VDA/VDMA working groups,
    the VDA5050 GitHub repository, MassRobotics/OPC UA companion work): report
    ambiguities you find as spec issues, and cite them in check docs.
11. A security-reviewed reference deployment: Terraform/Helm with TLS on the
    MQTT broker by default (today plaintext is the default; `docs/COMPLIANCE.md`
    lists it as a gap), mTLS per robot, ACLs scoped to each serial number.
12. Governance for longevity: a second maintainer, a public roadmap, a
    CHANGELOG-per-package for the publishable packages, and a one-year support
    statement for each minor release.

## What to do this week (ordered)

1. Enable Discussions and secret-scanning validity checks; set repository topics. *(Owner action.)*
2. Configure the PyPI trusted publisher (pypi.org, workflow `release.yml`, environment `pypi`).
3. Verify clause numbers (P0.2) and add the official-schema layer (P0.1).
4. Reserve the PyPI names, add the release workflow, publish `yantra-conform`.
5. Cut the first releases (`conform-v0.1.0`, `v0.14.0`) once the PyPI trusted publisher is configured, then add `lint` and `python (tools/conformance)` to the required checks.

## Reproducing the checks in this audit

```bash
python scripts/secret_scan.py --history
cd core && python -m pytest tests -q               # includes the SSRF guard suite
cd notifier && python -m pytest tests -q
gh api repos/CD-LC/yantrafleet/branches/main/protection   # 404 = unprotected
```
