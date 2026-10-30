# Governance

Yantrika is a maintainer-led open-source project under the MIT licence.

## Roles
- **Maintainer** - merges changes, cuts releases, owns the security process.
  Currently: Punith Nagaraju ([@punith-naga](https://github.com/punith-naga)).
- **Contributor** - anyone who sends an issue, review, doc fix or patch.
- **Committer** (earned) - after a sustained record of good, reviewed
  contributions to a component, a contributor may be invited to review and
  merge changes in that component. Security-sensitive paths (`supabase/`,
  `core/yantracore/netguard.py`, `ops/yantraops/sandbox*`, `deploy/`,
  `.github/`) always need the maintainer's review (`.github/CODEOWNERS`).

## Decisions
Small changes: one approving review. Behaviour, schema or wire-format changes:
discussed in an issue first, and a schema change is always a *new* numbered
migration. Disagreements are resolved by the maintainer after a good-faith
attempt at consensus; the reasoning is written on the issue.

## Specification fidelity
Where this project implements or grades VDA 5050, the specification wins over
convenience. A conformance check must cite its clause; a change that makes a
check stricter or looser is a behaviour change and is called out in the
changelog. Disputes go through the *VDA 5050 conformance question* form.

## Releases
Semantic versioning for the fleet release (`core/yantracore/version.py`),
tagged `vX.Y.Z`, with a `CHANGELOG.md` entry. Security fixes are released as
soon as they are ready and credited (with consent) in the advisory.

## Becoming a maintainer / project continuity
Open an issue titled "Maintainer nomination" with links to prior work. If the
sole maintainer becomes unreachable for 6 months, the most active committer
may ask GitHub to be made maintainer; the licence guarantees the code stays
forkable regardless.
