# Task4 #332 — real GitHub CreateRef trial preauthorization review (OFFLINE ONLY)

## Central invariant

A synthetically valid A/B/C receipt bundle is NOT authorization to create a Git ref and NOT evidence that two genuinely independent GitHub-hosted runs raced. This PR records a fixed, fail-closed **review gate** and keeps every real write and Provider gate off. It neither grants consent nor starts any workflow.

Evidence carried forward from #331 (GitHub-hosted offline run only): Run 38138979918, Job 114468691107, main SHA `6ef46b4cf49685a2599adc98ed0498de4575e1f8`, pytest 51/51 PASS, Artifact 11701243750, ZIP SHA-256 `6acf07de97712a6598cee34d926da394eeadaa3b02c88f55e5ee4a4373a2c5dc`. These are evidence of **offline validator operation**, not an actual cross-run CAS trial.

## Frozen future GitHub-only experiment scope, NOT authorized

- Repository: `veritasfuji-japan/veritas-task4-cas-lab` (private, disposable research lab); no production endpoint.
- Candidate ref: `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73`
- Target existing commit proposed: `9edd28eee24da559fc0ad24fd97291944acc2ed4`. The remote object's current existence and exact type MUST be re-fetched at execution preflight; this document is not that check.
- Proposed POST path: `/repos/veritasfuji-japan/veritas-task4-cas-lab/git/refs`; GET path and hashes in contract.
- Four genuinely distinct GitHub-hosted run/job identities, in order: read-only PREFLIGHT → two manually started A/B write attempts → read-only independent C. Exact one POST per A and B maximum, no retries, including on UNKNOWN. Chronological dispatch is NOT enough to claim an actual race; capture timing/interleaving evidence or classify only as distinct-run serial CreateRef uniqueness.
- Proposed engineering ceiling **4 × 8 job minutes = 32 runner-minutes total**, subject to actual billing and quota verification; **this is NOT an approved spending allowance or guarantee**. No billable larger runner. Timeout does not by itself cap charges or all side effects.
- Future GitHub write workflow (NONE here) must use only a reviewed pinned default-branch source, `workflow_dispatch` only, selected repository, non-PR code, no untrusted fork input, least privilege and isolated short-lived `contents:write` token. The permission is repository-wide and is not restricted to one ref by the API: an independent code/review boundary matters.
- No Provider token, OpenAI/other Provider request, actual bank effect, credential installation, or real model Utility scoring.

## Preconditions for a separate fresh owner approval (all remain NOT VERIFIED or NOT GRANTED)

| Gate | Required evidence before later execution | Current |
| --- | --- | --- |
| Scope | Exact repo/ref/target, independent authenticated object checks, preflight evidence | **not attested** |
| Source | Reviewed proposed writer and its immutable commit SHA, workflow path & contents digest | **not fixed; writer absent** |
| Access | Explicit GitHub `contents:write` review, workflow dispatch restrictions, no PR trigger, no broader token | **not authorized** |
| Ownership | Who can DELETE/PATCH/recreate the ref; branch protection/ruleset/admin bypass | **not independently attested** |
| Budget | Actual remaining private Actions minutes, minute cap, billing controls and abort criteria | **not verified** |
| Consent | Fresh, exact owner permission for at most two POSTs and four bounded runs | **not granted** |
| External evidence | Independently retrieved Run/Job IDs, checkout/workflow SHA, normalized HTTP responses, GET ref and artifact digests | **not observed** |

**Approval transaction must happen after the eventual writer code has been reviewed and the final merged commit SHA is known.** Never put an invented future SHA in the approved plan. Any subsequent branch or workflow change invalidates the pin and requires renewed review.

## Classification of a later authorized trial

1. PREFLIGHT: independent authenticated repository, ref and target object queries. A 404 alone may be access masking; require corroborating repository access. A preflight miss does not prove lifetime absence.
2. A/B: independent hosted runners/Run IDs/Job IDs/run_attempt=1, same frozen workflow source, request body, target and ref. Separate one-shot POST journals; no hidden HTTP client retries; no re-dispatch after UNKNOWN. Inspect sanitized 201 and exact returned ref + SHA. A 422 is **not** duplicate proof by itself; validation failures must be rejected, with independent state evidence.
3. C: newly launched read-only Actions Run, authenticated GET of exact ref and independent retrieval of A/B provenance. Compare time ordering, exact request hashes, HTTP response evidence and workflow/run/job facts. Evidence signed only by the writers is not independent attestation.
4. Even a clean 201 + validated duplicate + GET does **not** prove non-resettable consume-once authority or production bypass resistance. GitHub administrators may force-update, delete or recreate refs; separate custody and durable ledger remain open.

Stop and classify DENY/UNKNOWN on insufficient permission, unexpected ref presence, SHA/actor drift, ambiguous 422, timeout, incompatible billing cap, credentials in the wrong context, evidence provenance mismatch or unauthorized workflow change. **No auto retry**, no deletion/reset of the proof ref to re-run the experiment.

## Work shipped by this review PR

- Frozen machine-readable scope and unmet authorization fields.
- Local-only strict review script with a report SHA-256 and refusal on altered fields or enabled source gates.
- Negative tests for unauthorized claims, target/ref drift, budget misuse, owner consent spoofing and policy mismatch.
- A manual-only `contents:read` offline test workflow. **Do not dispatch it without fresh, separate private Actions minute consent.** It is not a writer; there are no POST endpoints or provider secrets in its job.

This review does **not** alter `REAL_GITHUB_WRITE_SOURCE_GATE=False`, `APPROVED_WORKFLOW_HEAD_SHA=None` or `LIVE_PROVIDER_DISPATCH_ALLOWED=False` in #330. Related [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
