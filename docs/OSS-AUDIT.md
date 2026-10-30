# Open-source standards audit and the road to "the" VDA 5050 platform

Audited 2026-10-30 against the repository at `main`. Scores are the
auditor's judgement, not a certification; each line says what the score rests
on so you can disagree with it.

**Overall: 7.5 / 10 today** (about 6.5 before the changes made with this audit).
**9 needs the items marked P0/P1 below** - mostly distribution, branch
protection and spec-fidelity work that cannot be done by editing files alone.

## Scorecard

| Area | Before | Now | Rests on |
|---|---|---|---|
| Security of the code | 7 | 8 | SSRF guard added; RLS/RBAC, command gate, HMAC webhooks, rate limits, secret scan in CI. Console still relies on sanitise-on-read (see S2). |
| CI and supply chain | 6 | 7.5 | Actions pinned to SHAs, CodeQL, Scorecard, dependency review, pip-audit, least-privilege token. No branch protection, SBOM, signing or provenance. |
| Community and governance | 5 | 7 | CoC, governance, support, CODEOWNERS, issue and PR templates, SLA and safe harbour added. One maintainer; Discussions off; no roadmap or "good first issue" labels. |
| Packaging and distribution | 3 | 3.5 | Nothing is installable with `pip install` or `docker pull`; the README says `git clone`. Biggest gap for adoption. |
| Engineering quality | 7 | 7 | 700+ offline tests and a documented test contract are unusually good. No linter, type checker or coverage gate; 5k-line single-file console; one flaky subprocess test in `ops`. |
| VDA 5050 credibility | 6 | 6.5 | Real 52-check conformance tool, independent from the simulator, zero dependencies. Not yet validated against the official JSON schemas; v2.1 only; no public results. |

## What was wrong, and what was fixed here

### Security

| # | Finding | Severity | Status |
|---|---|---|---|
| S1 | **SSRF.** `WEBHOOK_URL`, the Twilio SID and `CONNECTOR_MQTT_HOST` are editable by a console `admin` (via `app_settings` / `app_config`) and were used for server-side requests with no validation. An admin (or XSS in an admin session) could make the notifier POST to `169.254.169.254`, loopback services or the VPC, and could inject path segments through the SID. | High | **Fixed.** `core/yantracore/netguard.py`: https only, no embedded credentials, every resolved address must be public, metadata/link-local always refused, no redirects, fail-closed DNS, SID percent-encoded; MQTT host refuses metadata but allows LAN. 40+ tests incl. IPv4-mapped, 6to4, multi-record DNS. Opt-in knobs for internal targets. |
| S2 | Console XSS defence is a **sanitiser on the read path** (`Sync.q()`), with ~190 template sites and 47 `innerHTML` uses. One missed path re-opens stored XSS; look-alike character swapping also silently alters data. | High (latent) | Open. Move to output-encoding helpers (tagged template that escapes by default), forbid raw `innerHTML` with a lint rule, and ship a CSP without `unsafe-inline` plus Trusted Types. |
| S3 | **Every component defaults to the maintainer's Supabase project** (`DEFAULT_SUPABASE_URL` in sink, copilot, detector, notifier, connector). A fork or a first-time user who forgets `SUPABASE_URL` sends fleet telemetry to someone else's database. | High (privacy) | Open. Fail closed: require `SUPABASE_URL` unless `--demo` is passed, and print the destination at startup. |
| S4 | Copilot `/ask` is **open unless `SARATHI_TOKEN` is set** and CORS admits the `null` origin. Insecure by default. | Medium | Open. Refuse to bind a non-loopback address without a token; drop `null` from the default CORS list. |
| S5 | DNS-rebinding window between the SSRF check and the connect. | Low | Documented in `netguard.py` and `docs/SECURITY.md`. Close it by connecting to the vetted IP, and add IMDSv2 hop-limit 1 / egress rules at the host. |
| S6 | No supply-chain provenance: no SBOM, no signed releases, no hash-locked requirements. | Medium | Open (P1). |

### Repository and process

| # | Finding | Status |
|---|---|---|
| R1 | `main` has **no branch protection** (GitHub API: "Branch not protected"). Scorecard and every serious adopter check this. | Open - needs the repo owner (settings, not a file). |
| R2 | Actions used floating tags (`@v4`). | Fixed - pinned to commit SHAs with version comments; Dependabot keeps them current. |
| R3 | The connector CI job never installed `mcap`/`paho-mqtt`, so its import tests errored. | Fixed. |
| R4 | Dependabot covered 3 of 10 Python components. | Fixed. |
| R5 | Missing CoC, governance, support, CODEOWNERS, issue/PR templates, response-time and safe-harbour policy. | Fixed. |
| R6 | GitHub Discussions disabled; no topics set; no GitHub Releases. | Open - repo settings. |
| R7 | `ops` suite has a timing-dependent test (spawns real processes on ephemeral ports) that failed once under load and passed on rerun. | Open - quarantine with a retry marker or make it event-driven. |
| R8 | No linter / formatter / type check / coverage gate. | Open (P1): ruff + mypy on `core`, `tools/conformance`, `notifier`; coverage floor. |

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

1. Turn on branch protection for `main` (require PR, CI green, CODEOWNERS review, no force-push) and enable Discussions and secret-scanning validity checks. *(Owner action.)*
2. Close S3 and S4 (insecure defaults) - small diffs, large trust gain.
3. Verify clause numbers (P0.2) and add the official-schema layer (P0.1).
4. Reserve the PyPI names, add the release workflow, publish `yantra-conform`.
5. Add ruff + mypy + a coverage floor to CI.

## Reproducing the checks in this audit

```bash
python scripts/secret_scan.py --history
cd core && python -m pytest tests -q               # includes the SSRF guard suite
cd notifier && python -m pytest tests -q
gh api repos/CD-LC/yantrafleet/branches/main/protection   # 404 = unprotected
```
