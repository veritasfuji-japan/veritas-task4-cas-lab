# Task4 #331 — Independent GitHub Actions A/B/C receipt proof planning (OFFLINE ONLY)

## One proof invariant and precise claim

The future authorized experiment must prove that **two distinct GitHub-hosted Actions runs** each attempted exactly **one** CreateRef request for an identical frozen candidate Git ref in the isolated lab, with exactly one HTTP 201, one independently substantiated conflict, and an independent read-only Git ref GET returning the fixed target SHA.

A separate run must also establish the ref did not exist before the race; this raises the evidence plan from A+B+C to **four roles**: **PREFLIGHT, A, B, C**. Each role needs its own Run ID and Job ID. A and B can win in either order. No automatic retry is allowed, especially after HTTP timeout or an unknown response.

**This PR does NOT carry out that experiment.** Every receipt in the current Python fixtures has `origin=SYNTHETIC_OFFLINE_ONLY` and can never be promoted to real GitHub provenance; the artifact report always states `real_github_cross_run_cas_proven=false`.

## Frozen lab-only scope

| Item | Exact value |
|---|---|
| Lab repository | `veritasfuji-japan/veritas-task4-cas-lab` (PRIVATE) |
| Source benchmark | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| Source benchmark SHA | `e3365d35054c06df09a37f3f4926bbe6c2fdba06` |
| Prior merged lab main | `40b98037a1cb28362de2ac414c98837409ea686c` |
| Candidate ref | `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` |
| Ref target | `9edd28eee24da559fc0ad24fd97291944acc2ed4` |
| Future CreateRef | `POST /repos/veritasfuji-japan/veritas-task4-cas-lab/git/refs` |
| Future independently attested GET | `GET /repos/veritasfuji-japan/veritas-task4-cas-lab/git/ref/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` |
| API token or actual ref write | **NONE IN THIS PR** |
| Provider API / real banking effect | **DENY** |

## Required future evidence

The **PREFLIGHT** hosted Run must independently observe that the exact ref is absent. A later authorized run's preflight GET status 404 is only one context-specific observation and should be interpreted along with the repository/path, credential and the complete response (404 alone can also mask repository access). No proof can claim the ref was absent forever.

**Run A and Run B** must be distinct workflow_run IDs and jobs on genuinely distinct GitHub-hosted runner sessions and must use the same pinned `GITHUB_SHA`, `GITHUB_WORKFLOW_REF`, exact ref and target, one POST maximum per authorized Run. The win can be A **or** B. A 201 with an exact ref/object SHA match is a candidate create; 422 is not automatically a collision (it can be invalid input). Capture sanitized response, exact request-body SHA, occurrence timestamps, workflow/job IDs, run_attempt (must be 1), and remote checkout SHA. The result of an API timeout/409/422 with unrelated validation error is **UNKNOWN or DENY**, not an invitation to retry.

**Run C** must be a NEW read-only GitHub-hosted Actions Run, with no CreateRef permission, to GET the exact ref and verify its target SHA. It must also independently fetch the provenance of A/B and audit the ref with GitHub's authenticated REST API, rather than trusting self-declared JSON artifacts or their hashes. A self-generated SHA-256 checks artifact bytes but **does not authenticate the source**.

Our strict validator currently accepts only **synthetic** fixtures and rejects changed Run IDs, reused jobs, changed workflow actor/ref/head, tampered payload digests, ambiguous duplicates, malformed 201, wrong ref/target, unknown network responses, unauthorized Provider claims, and source gate changes. Passing only shows the *evidence format and refusal criteria* can be validated. It **cannot** establish that any real remote call happened.

## Separate approval still required — NOT AUTHORIZED

A future actual GitHub-only CAS test requires a **new explicit** owner approval defining:
- the exact lab repository, single candidate Git ref, immutable commit target, frozen workflow head and GitHub token capabilities
- at most two **single-POST** manual write-enabled runs plus independent read-only preflight/audit runs, no retries even after UNKNOWN
- permission to use repository-scoped `contents:write` in a specifically reviewed manual-only workflow, **never** from untrusted PR code or from auto-triggered pull requests
- maximum GitHub Actions runner-minutes and an abort condition; the lab's PRIVATE Actions usage and budget should be rechecked before dispatch
- audit of actors who could delete, force-update or recreate the ref. Git refs are not independently administered non-resettable durable consume-once authority. Do not destroy the proof ref to test deletion.

No existing approval of a read-only CI run permits any CreateRef mutation. No current approval authorizes OpenAI/other Provider API calls, credential installation, cost, genuine model Utility scoring or real financial effects. Historic Provider consent remains spent.

The only new enabled workflow here is `.github/workflows/task4-331-offline-evidence-review-manual.yml`, which is **workflow_dispatch only**, `contents:read`, without GitHub write token, external API calls or automatic PR/push triggers. **NOT AUTHORIZED**: running new write-capable workflows or doing the real GitHub ref experiment.

Related: [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
