# Task4 #342 — FINAL REAL CAS APPROVAL AND INDEPENDENT AUDIT PLAN (NO WRITE AUTHORITY)

> **Status:** REVIEW-ONLY. NO GitHub CreateRef POST, no writer workflow, no paid Provider calls, no new credential, no owner consent. A merged PR, a green CI or a prior approval is NEVER a new authorization.

## Purpose and evidence already established

Task4 #340 authenticated five real GitHub GET requests in an owner-triggered `contents:read` Action: [Run 38186765875](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38186765875), Job 114610648509, HEAD `cd1d137da8af98620ddd59f9adc1bee889128955`. JUnit 302/302 PASS. Artifact 11719338461, ZIP SHA-256 `51e4af5d773b2c158cc128b45b1bb2501980d84c6e10b37aae4526be0c550a34`. Exact protected reference was observed **404** at that moment, but the runner's read-only token could not see the Ruleset bypass actor list.

Task4 #341 independently reviewed the frozen read-only report with a separate GitHub REST Ruleset field snapshot: [Run 38187628606](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38187628606), Job 114613290354, HEAD `f48021f737a66f119569ac586f8d6ad4b1de34d9`. 261/261 PASS, Artifact 11719839558, ZIP SHA-256 `26746b9f9c4271a56210749306d12619e1ce46588318060591ecfc3f58e5d0ae`. The separate read observed `bypass_actors=[]` and `current_user_can_bypass=never`, but there is **no signed simultaneous witness of the original runner**. No true race/CAS, admin-resistant irrevocability or enterprise external effect is proven.

## Frozen parameters (design, not permission)

- **Repository:** `veritasfuji-japan/veritas-task4-cas-lab` (public), ID `1414228001`.
- **Candidate ref:** `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73`.
- **Existing target commit:** `9edd28eee24da559fc0ad24fd97291944acc2ed4`.
- **Ruleset:** `24880024`, `updated_at=2026-10-11T22:00:45.379+09:00`, expected deletion/non-fast-forward/update rules, no bypass actors. An administrator with appropriate access may modify/reset the Ruleset; do **not** claim immutable enforcement.
- **Future writer workflow (ABSENT):** `.github/workflows/task4-330-authorized-create-ref.yml`.
- **Four roles (planned only):** PRECHECK, A, B, C (manifest labels: `PREFLIGHT,A,B,C`). PRECHECK must run without a writer token. A and B would be separate jobs/runs and ephemeral credentials; C would audit without write permission, with independent external credential/custodian evidence where needed.
- **Planned caps:** at most four workflow runs, at most 2 total CreateRef POST requests, at most one per writer, **zero retries or replays**, 8 runner minutes per run, 32 runner minutes aggregate. These limits **are not authorization**, and runner-minute/cost limits still require a separately approved budget.
- **Provider:** prohibited, no bank/LLM API effects.

## Explicit consent and exact SHA required *later*

A future, separate, unambiguous user authorization must identify **all** of: the final writer workflow HEAD SHA and its reviewed workflow file SHA, repository ID/name, exact candidate ref, existing target commit SHA, Ruleset ID and security-relevant state, authorized GitHub credential type/scope, actor and time window, four-role mapping, maximum runs/POSTs/retry limits, dollar or usage-cost ceiling, unique consent record and expiry. Approval must remain valid **at dispatch and at each POST boundary**; it cannot be inferred from issuance-time approval.

A GitHub `contents:write` workflow token is repository-scoped and cannot be assumed limited to one ref. Any privileged connection must have its blast radius explicitly reviewed. A future implementation MUST re-check Ruleset and candidate ref before issuing any POST, AND fail closed if bypass visibility is absent or conditions change. Installing any writer workflow or enabling source gates requires its own PR review AND separate explicit owner consent. The #342 freeze itself intentionally pins approval fields to `null`/`false`.

## Independent audit and actual race acceptance criteria

A designated **independent read-only** observer should check run IDs, job IDs, commits, workflow blob hashes, per-run/per-request timestamps, real REST statuses and response digests, the exact single POST body per writer, server-side final ref state, the actual total POST count, and relevant Ruleset/bypass state *at execution*. Use signed audit records when possible, or clearly mark unsigned/missing evidence. Do not disclose tokens or raw Authorization headers.

To call this a **cross-run race** there must be two truly distinct jobs/runs with separately scoped ephemeral tokens, defensible overlapping execution windows and unambiguous server receipts. A single HTTP 201 and 422 (or two offline synthetic statuses) **does not by itself** prove overlap. An HTTP 404 at preflight is NOT CAS; Ruleset protection cannot prove the ref is admin-irreversible.

**Fail closed without retry** on an absent owner authorization, unpinned or changed workflow/head, modified Ruleset, missing bypass assurance, unexpected GitHub HTTP response, ambiguous POST result, ref already present, changed target commit, exceeded time/run/budget caps, or missing audit evidence. A failed/ambiguous write must not be retried automatically, because the server may already have committed a change.

## PR scope

- New frozen contract: `contracts/TASK4_342_REAL_CAS_FINAL_APPROVAL_AUDIT_REVIEW_ONLY_V1.json`.
- New offline-only verifier: `scripts/task4_342_final_cas_approval_audit_review_only_v1.py`.
- New negative suite: `tests/test_task4_342_final_cas_approval_audit_review_v1.py`.
- Existing **manually dispatched, credential-blank, `contents:read`** offline review workflow runs it and emits JUnit, canonical report digest, file SHA-256 and Artifact. No new writer workflow or privileged step is added.

### Precise conclusion

**What will be checked by #342 CI:** static plan compatibility, pinned predecessor evidence and source-disabled writer gates, explicit consent absence, strict planned bounds, denial on any field promotion.

**What #342 will never prove:** consent for a POST, real GitHub simultaneous CreateRef, admin-proof consume-once, or safe model/banking Provider effects.

Research issue: https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321.
