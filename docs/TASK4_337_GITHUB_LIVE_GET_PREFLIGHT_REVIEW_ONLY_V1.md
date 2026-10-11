# Task4 #337 — final prewrite live-GET candidate and explicit authorization boundary (OFFLINE)

## Central invariant

**A correctly shaped snapshot from five exact GitHub REST GETs cannot by itself authorize CreateRef.** This change implements reusable, fail-closed, exact-scope checks, an HTTPS GET-only transport behind a literal-disabled source gate, synthetic negative tests, and a review-only artifact. There is no executable GitHub writer or Provider dispatch and no real GitHub GET/POST in CI. The existing #330 writer gate is unchanged (`False`).

## Concrete future observation endpoints

Every legitimate future A/B writer must freshly perform the following independently authenticated GET requests just before any proposed POST, using a reviewed token/runner and the exact source SHA.

1. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab` — HTTP 200, repository id `1414228001`, exact owner/name, `private=false`, `visibility=public`, default branch `main`.
2. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/commits/main` — HTTP 200, exact SHA equals the separately approved running workflow SHA. The current reviewed baseline is `03cc2f9f340605c32f16fd328ac18389fe64639b`, **not** a future approved SHA.
3. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/git/commits/9edd28eee24da559fc0ad24fd97291944acc2ed4` — HTTP 200, exact fixed existing commit SHA.
4. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/rulesets/24880024` — HTTP 200; require frozen `active`, no bypass, exact ref pattern, `deletion/non_fast_forward/update` and last-reviewed update timestamp `2026-10-11T22:00:45.379+09:00`. Any drift fails closed.
5. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/git/ref/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` — HTTP 404 with a GitHub Not Found body, not HTTP 403/422, wrong ref, malformed or absent response.

This GET list is an execution precondition, **not** a guarantee of future absence or security against all admin actions. Both A and B may only POST after their own preflight 404; if B sees the ref already existing, it must stop with no POST. Under that outcome the experiment has a useful single-creation result but **not** a measured simultaneous collision; do not misrepresent it as one.

All five REST responses are untrusted data until provenance is independently captured and validated against GitHub. The included fixtures are explicitly synthetic. `updated_at` checks are time-of-check snapshots rather than irrevocable lock proofs. A signed hash of self-generated JSON is not a GitHub signature.

## Implemented boundaries

- New `scripts/task4_337_live_get_prewrite_boundary_review_only_v1.py` has `verify_five_exact_gets` (strict exact shape) and `validate_readonly_transport_request` (method GET and five frozen paths only).
- There is a **future GET-only HTTPS client**, but it is unreachable by default: `LIVE_READONLY_NETWORK_GATE=False`, `EXTERNALLY_APPROVED_WORKFLOW_SHA=None`. No active Actions job invokes it; not even a read-only real call occurs in the review run.
- `real_create_ref_once` unconditionally denies, including forged approval args. #330's existing dormant writer remains unmodified and source gated closed.
- Unknown/mismatched response, different repository, wrong main or target SHA, changed Ruleset or bypass, missing/ref 403, and arbitrary GET/POST/DELETE path are all rejected in negative tests.
- The existing manual-only `contents:read` review workflow is extended with #337 offline-only test/JUnit/report and SHA-256 artifact output. No `contents:write` executable workflow installed; staged #336 YAML stays under `docs/templates`.

## Remaining steps (no authorization implied)

1. Independent audit the exact final writer and preflight implementation including actual GET provenance, SHA and token boundaries, real collision timing evidence, role-specific signed output and genuine C readback.
2. Separately review an installation PR for a manual-only writer with the smallest available write permission (GitHub's `contents:write` is still repository scoped, not restricted to a single ref). Unreviewed workflow merges or environment toggles must not activate anything.
3. **After the executable workflow merges**, freeze its real merged SHA outside source, obtain a fresh explicit owner authorization for exactly the repo/ref/commit, maximum two A/B one-shot POST attempts and four distinct run roles, no retries and no Provider API. Don't reuse earlier approvals.
4. Confirm public-hosted Actions cost settings; collect A/B exact run/job IDs, timestamps, request/response hashes, independent C readback. A bare 201/422 pair is insufficient for GitHub-independent, non-resettable single-use authority.

The GitHub Ruleset can be modified by sufficiently privileged administrators; this proof cannot infer truly external admin-independent authority or production Permission Bind from GitHub alone.

**Classification:** TASK4_337_SYNTHETIC_GET_SHAPE_VALID / REAL_GET=0 / REAL_POST=0 / EXTERNAL_APPROVAL=ABSENT / LIVE_CAS=UNPROVEN.

Related: [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
