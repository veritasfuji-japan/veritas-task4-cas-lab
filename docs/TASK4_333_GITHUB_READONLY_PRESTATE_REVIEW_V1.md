# Task4 #333 — actual GitHub read-only prestate, fixed as an observation (NO WRITE)

## Rule-of-One

A successful **read-only GitHub GET** of a fixed commit plus a not-found observation for one candidate ref does not authorize a later CreateRef POST. A not-found response is not lifetime nonexistence, not a successful cross-run CAS experiment, and not immutable single-use authority.

This PR freezes **point-in-time observations retrieved on 2026-10-11** from the connected GitHub API in a JSON contract and tests their refusal semantics. The observations are manually transcribed into GitHub source: **NOT independently signed authenticated API response objects**. They MUST be refreshed directly at execution time in any separately authorized trial. The tests in this PR are offline; this PR performs no remote GitHub calls at runtime.

## Actual read-only GitHub API observations

| GET / subject | Observation | Limits |
| --- | --- | --- |
| Repository `veritasfuji-japan/veritas-task4-cas-lab` | Private, default branch `main`; readable by linked account | Does not establish admin-independent custody |
| `GET /repos/.../commits/main` | SHA `ee69b8a5e936354b9cf1f24e311b08ce593fde92` | This is the source snapshot before #333 |
| `GET /repos/.../git/commits/9edd28eee24da559fc0ad24fd97291944acc2ed4` | 200-success, exact commit SHA matches | Existing commit does not authorize a new ref |
| `GET /repos/.../git/ref/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` | 404 Not Found | Not alone lifetime nonexistence; can also reflect authorization masking |
| `GET /repos/.../git/matching-refs/heads/offline-test-ledger/` | Empty list | Corroborating namespace observation, not an atomic lock |
| `GET /repos/.../rulesets` | 403: "Upgrade to GitHub Pro or make this repository public to enable this feature." | Cannot claim required ruleset protection exists |
| `GET /repos/.../branches/main/protection` | 403: "Resource not accessible by integration" | Cannot attest protection or admin bypass |
| Private Actions remaining minutes / budget controls | NOT AVAILABLE through this connection | Must confirm in Settings → Billing and licensing before future dispatch |

GitHub evidence for the predecessor offline-only #332: [Run 38139656085](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38139656085), Job 114470698728, 35/35 tests, Artifact 11702366273, ZIP SHA-256 `d084399be98e8591cbaabc93b17e75986cf838a4ec263dd03d7beaa5fc00370c`. This attests only the earlier offline checks' execution (not actual A/B CreateRef).

## Preconditions to move from read-only evidence to real GitHub-only trial

1. **New runtime preflight** from a separately identified GitHub-hosted run must verify access to private repo and the target commit, and then absence of exact ref. A 404 without corroborated repository access must be UNKNOWN.
2. **Frozen writer**: another reviewed PR must contain the exact one-ref writer, its final Git SHA and a manual-only workflow, with no PR/push triggers. Do not insert an anticipated commit SHA.
3. **Protection and custody**: inspect branch/ruleset capabilities and permissions, including owners/admins who can delete or force-update/recreate the ref. At present rulesets may be unavailable for this private repository on the current plan, and branch protection has NOT been checked by an authorized integration. Treat Git ref as a **resettable research object**, never an independently administered irrevocable ledger.
4. **Private Actions budget**: before any further manual Actions execution confirm remaining allowance, spending limit and expected worst-case minutes. A proposed 4×8 = 32 runner-minute ceiling is not a billing guarantee or payment authorization.
5. **New exact owner consent**: separate explicit scoped permission for precisely this repo/ref/target, two one-shot real POSTs maximum across Run A and B, at most 4 hosted-run roles PREFLIGHT/A/B/C, no retries and no Provider key/API. No existing approval carries forward.
6. **Independent after-the-fact GET and audit** by Run C, with real Run/Job IDs, original request-body digest, response status and body, observed ref SHA and provenance. Demonstrate actual request overlap if claiming a *race*. A 201 and a 422 alone are insufficient to claim a non-resettable control plane.

Unknown, identity mismatch, permissions failure, missing budget cap or lack of fresh consent ⇒ **DENY / NO WRITE / NO RETRY**. Never delete or reset the candidate ref to run the experiment again.

## Code changes and safeguards

- New frozen observation manifest plus local-only refusal validator, negative tests and documentation.
- No new GitHub Actions workflow: the prior #332 guard requires exactly 4 read-only manual workflows. All existing workflows and #330 write/Provider source gates stay unchanged.
- No Github API client or network code in the newly added verifier.
- No self-attested SHA is treated as GitHub signature or independently administered authority.

**Classification:** `READ_ONLY_OBSERVATION_RECORDED / BILLING_UNVERIFIED / PROTECTION_UNVERIFIED / REAL_CAS_UNPROVEN / PROVIDER_DENY`.

Related tracking: [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
