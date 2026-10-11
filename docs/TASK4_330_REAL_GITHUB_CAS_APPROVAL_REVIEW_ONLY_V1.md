# Task4 #330 — Review-only real GitHub CreateRef candidate (source-gated OFF)

## User authorization and hard boundary

Owner approved only a **Draft PR** containing the future GitHub-only CAS client, review tests and conditions for a possible separately authorized two-Run trial in the private isolated lab.

**NOT approved:** any real GitHub ref creation, contents-write workflow activation, Actions dispatch, new token use, real OpenAI Provider calls, billing spend, or bank effects.

The reviewed source uses literal REAL_GITHUB_WRITE_SOURCE_GATE=False and APPROVED_WORKFLOW_HEAD_SHA=None. This prohibits entering the actual HTTPSConnection even with a forged environment or fake token. A separate explicitly approved PR must change these constants and add an authorized default-branch write workflow. The current source contains only a **manual, contents:read review workflow**. It has no PR or push trigger, and it has not been dispatched by this PR. This is intentionally safer than merging a live write-capable Action and relying on a human not to click Run.

## Frozen research scope

| Field | Frozen value |
|---|---|
| isolated lab | veritasfuji-japan/veritas-task4-cas-lab (PRIVATE) |
| prior merged lab main | 9edd28eee24da559fc0ad24fd97291944acc2ed4 |
| RCC/REVAS source main | e3365d35054c06df09a37f3f4926bbe6c2fdba06 |
| proposed exact ref | refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73 |
| fixed ref target commit | 9edd28eee24da559fc0ad24fd97291944acc2ed4 |
| future POST | https://api.github.com/repos/veritasfuji-japan/veritas-task4-cas-lab/git/refs |
| future separate GET | /repos/veritasfuji-japan/veritas-task4-cas-lab/git/ref/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73 |
| real ref writes performed | **ZERO** |
| writable workflow currently activated | **NONE** |
| Provider dispatch | **DENY** |

The future POST has ONE and only ONE fixed JSON body with the ref and target sha above. No arbitrary caller-selected ref or repository, redirect following, force, DELETE, PATCH, retry, Provider API key, or production bank code.

## Steps after **separate explicit permission**

1. Freeze and independently verify exact target test ref and existing target commit, owner lab main SHA at authorization time, workflow SHA, GitHub personal account Actions minutes/budget cap, collaborators, protection/ruleset bypass, and a blank trial ref namespace. Capture written approval for one exact ref and two manual distinct Actions runs A/B plus optional third read-only run C. The permission must specify the GitHub token scope, a maximum private runner-minute budget and abort conditions. Contents:write allows broader repository mutation; the fixed ref name is **not an API-level token restriction**.
2. In a *separate reviewed PR*, change the hard source gate and exact workflow SHA, then install a manual-only contents:write workflow on the lab default branch; do not run it on untrusted PR code. Do not add Provider credentials or billing approval. No task here automatically authorizes a later real-model test.
3. Trigger two **different** GitHub-hosted Actions Run IDs on separate runners. Each may attempt exactly one real POST to the same test ref and frozen target SHA. Collect run IDs, job IDs, HEAD SHA, request-body hash, sanitized response status/body hash, ref and object.sha. No automatic retry even after network timeout/UNKNOWN.
4. HTTP 201 is only a candidate success if returned ref and object SHA exactly match. HTTP 422 alone is **NOT** evidence of a duplicate; validation error is also possible. HTTP 409, 401/403, 5xx, malformed reply or timeout is UNKNOWN/DENY. No Provider privilege follows from an HTTP status.
5. Independently run a third GET-only auditor C on a new hosted runner. It must verify the ref still points to the frozen target and correlate the A/B/C run and artifact SHA records. Do not delete or reset the ref afterward.
6. Audit who can force-update/delete/recreate the Git ref, including repo admins. Git ref uniqueness while a branch exists does **NOT** establish externally managed, irrevocable consumption. Production Provider dispatch remains denied until a separately governed ledger and fresh owner consent exist.

Historical Provider approval has been consumed. The benchmark's model Utility, injection, billed model-token caps and real bank effects have **NOT** been retested by this lab.

## Executable boundaries

- The actual Actions workflow under .github/workflows/task4-330-review-only-manual.yml is manual-only and read-only. A merged PR will not start it automatically. The private Actions usage budget and included minutes were observed in owner screenshots, but no blanket charge guarantee is implied.
- A future write-workflow **example only** is stored under docs/templates/task4-330-future-create-ref-WRITE-INERT.example.yml, outside .github/workflows, with a disabled if:false job. It must not be moved or enabled without explicit consent.
- The Python candidate real function exists for review but is source-gated OFF; it cannot reach api.github.com in the present PR. Unit tests exercise only the synthetic 201/422/409/403/500/timeout classification and hard refusals with sockets disabled.
- No green CI claim may be made until a separately approved read-only manual run or independent local tests have actually executed. A passing review test is not proof of genuine multi-run CAS.

Related: [RCC benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
