# Task4 #335 — exact Ruleset and future CreateRef prewrite review (SOURCE-GATED OFF)

## Central invariant

**A live GitHub API Ruleset snapshot may define future prerequisites, but can never authorize a real GitHub CreateRef POST.** This PR freezes the exact live-observed Ruleset shape, connects the candidate CreateRef body from #330, and adds negative tests. Nothing here enables a GitHub write API call, grants `contents:write`, provisions secrets or authorizes real-model Provider use.

### Independently observed external facts — 2026-10-11, not a runtime attestation

- Repository is public: `veritasfuji-japan/veritas-task4-cas-lab`; source `main` SHA `acdb15defa5781ffe64d4ae7b2629640abe4812c`.
- Exact target ref `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` returned GitHub GET **404 Not Found**. A second GET at actual execution time remains necessary and a 404 alone is not lifetime absence.
- Target commit `9edd28eee24da559fc0ad24fd97291944acc2ed4` existed when inspected.
- GitHub repository Ruleset [24880024](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/rules/24880024) was retrieved by authenticated GitHub GET. `active`; `target=branch`; exact included ref, zero excludes; bypass actors empty; `current_user_can_bypass=never`; rules `deletion`, `non_fast_forward`, `update`. Creation deliberately unrestricted. Ruleset updated at `2026-10-11T22:00:45.379+09:00` at last observation. This snapshot can become stale.
- `Applies to 0 targets` is consistent with a presently nonexistent exact ref. It does **not** prove that enforcement will hold after the first creation, nor that an administrator cannot change Rulesets.
- Predecessor [#334 run 38140366944](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38140366944), Job 114472823935, #332 35 PASS + #333 30 PASS. Artifact 11702966070, ZIP SHA-256 `0a77ca0f7ca3d7d18db57db9b5ee1d37003e07b510b31f92f410a293452d8c38`. This is **offline** proof only.

The versioned JSON is a transcription of an observed live result, not a signed REST receipt or an automatically re-fetched independent attestation. A hash authenticates bytes within the report, not the identity of the GitHub response or independent rule custody.

## Planned future authorization scope — NOT GIVEN

| Item | Proposed (engineering limit only) |
| --- | --- |
| Repository | exact public isolated lab only |
| Git ref | `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` |
| Target existing commit | `9edd28eee24da559fc0ad24fd97291944acc2ed4` |
| Ruleset | exact Ruleset ID 24880024 and rules/target/update timestamp |
| Roles | distinct PREFLIGHT, A, B, C GitHub Actions Run & Job IDs |
| Writer attempts | at most ONE POST in A and ONE POST in B, no retries or redispatch |
| Read-only runs | PREFLIGHT and auditor C, new GitHub-hosted runner each |
| Max job duration | 8 minutes × 4 = 32 runner-minutes engineering bound, not an approval or billing guarantee |
| Provider calls | ZERO; no bank or monetary side effects |
| Source gate | `REAL_GITHUB_WRITE_SOURCE_GATE=False` with `APPROVED_WORKFLOW_HEAD_SHA=None` and Provider denied |
| Write-capable workflow | none exists in `.github/workflows` |
| Approval | missing; fresh explicit owner authorization required **after** final writer SHA review |

## Review-only implementation

- `scripts/task4_335_ruleset_prewrite_candidate_review_only_v1.py` loads the exact contract, compares every security relevant Ruleset field and refuses unknown/missing/bypass rules/target drift/update timestamp drift. It imports the frozen `#330` proposed CreateRef body and existing `#333` guard, but has **no GitHub network client**. Its `real_create_ref_once()` unconditionally denies even if provided a token or a forged approval environment.
- A future explicit, separately reviewed PR must implement a protected, manual-only GitHub workflow and live authenticated preflight of repository identity, fixed commit, ref absence and exact rule with no bypass. The current review function is deliberately not a future authorization gate; it cannot become a writer merely by supplying env variables.
- Even with future writer authorization, GitHub `contents:write` is repository-scoped rather than enforceable to one ref by token. Code-level restrictions, independent review, controller, and external custody remain open.
- A successful future 201 + unambiguous conflict + independent C readback proves at most a **scoped GitHub CreateRef uniqueness observation**. It does not prove unresettable/production-independent once-only permission, especially when repository admins can edit or disable Rulesets.
- This PR adds no new Actions workflow, and only adds one offline test step to the pre-existing manual `contents:read` workflow. No automatic triggers and no Provider tokens.

**Do not dispatch manual Actions without owner agreement; do not flip any write gate or create the experimental ref on the strength of this PR.** A future actual write requires scope/sha/time/budget consent and renewed preflight.

Related: [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
