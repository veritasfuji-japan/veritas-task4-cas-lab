# Task4 #338 — authenticated READ-ONLY GitHub Actions PREFLIGHT

## Rule-of-One

A manually triggered GitHub-hosted Action performs exactly **five authenticated HTTPS GETs** of the isolated public GitHub lab and produces a provenance-bound, content-hashed read-only Artifact. **This never grants a writer authority, never POSTs a Git ref, and never calls a model Provider.**

The authorization of running this read-only workflow is distinct from owner approval for creating/updating/deleting any Git ref. The #330 writer source gate remains False and no enabled writer workflow exists.

## Exact GET sequence

1. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab`, require ID `1414228001`, public, main default.
2. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/commits/main`, require remote SHA == this Action's `GITHUB_SHA` and checkout SHA.
3. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/git/commits/9edd28eee24da559fc0ad24fd97291944acc2ed4`, require frozen target SHA.
4. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/rulesets/24880024`, require Active, exact conditions, exact deletion/non_fast_forward/update rules and last-reviewed `updated_at`.
5. `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/git/ref/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73`, require explicit HTTP 404 Not Found.

Token `${{ github.token }}` is provided only to the manual #338 job (global `permissions: contents: read`). No checkout credential persistence, GitHub API POST, third-party endpoints or retry.

### Important GitHub Ruleset permission limitation

GitHub's REST docs say `bypass_actors` is **omitted** when the token doesn't have ruleset write permission. The manual GITHUB_TOKEN intentionally has *read-only* access. Therefore absence of this field MUST NOT be interpreted as an empty bypass list. The program records either:

- `FIVE_LIVE_GET_SHAPES_COMPLETE_NOT_AUTHORITY`: both bypass fields visible and safe; still **no POST permission**.
- `FIVE_LIVE_GETS_BYPASS_VISIBILITY_INCOMPLETE`: HTTP 200s, identity/ref/ruleset static shape checked, but bypass/admin custody incomplete; **cannot certify the complete writer preflight**.

It never broadens the token to `contents:write` merely to see bypass information. Separate admin-scoped inspection would still not prove immutable external custody.

### Execution instructions

After PR merge and offline static review, open [manual #338 Actions workflow](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/workflows/task4-338-live-authenticated-readonly-preflight-manual.yml) and select `main`, then `Run workflow` **once**.

This workflow is **manual-only**, owner-only, main-only and first attempt only. No automatic triggers. It writes the report plus optional pytest JUnit and SHA file only to local runner `results/*`, uploaded as an Actions Artifact. The report contains run ID, workflow ref, exact head SHA, GET path/status/body SHA-256, verdict. It does **not** contain bearer token or full response content, and is not a GitHub signed proof. The real Job ID, HTTP provenance and Artifact digest should be corroborated externally against GitHub REST following the run. The runner's token grants repository read only, not independent signature authenticity.

**Do not misclassify:** the Run ID for this PREFLIGHT does not authorize A/B; a future writer would require fresh and independently reviewed runtime preflight after *its own* merge-SHA and separate owner consent.

## Changes to legacy guard

#332 and #333 guard scanners now allow **exactly five named `workflow_dispatch` + global `contents:read`** workflows, with a single exception for `GH_TOKEN: ${{ github.token }}` in the new #338 workflow only. No old fixture was rewritten as public/PROVEN; historical private snapshot is retained. All actions remain read-only. The #338 workflow is the only additional runnable job and it is manually triggered.

## Caveats

An expired/changed ruleset, ref already existing, unauthorized runner/actor, 403, timeout or partial GET fails closed; no retry and no CreateRef attempt. If the Ruleset bypass list is withheld the result is incomplete even if the workflow is green. For real two-writer collision or provider-backed benchmark, new authorizations remain necessary.

Related: https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321
