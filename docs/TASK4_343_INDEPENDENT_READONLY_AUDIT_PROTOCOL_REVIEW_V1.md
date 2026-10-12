# Task4 #343 — Independent read-only observer protocol (DESIGN ONLY)

**Status: OFFLINE REVIEW ONLY.** This task does not run an independent observer, issue or verify an Ed25519 signature, approve a GitHub POST, install any writer workflow, change any Ruleset or access a Provider.

## Why this is necessary

- [#340 authenticated GET Run 38186765875](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38186765875) (head `cd1d137da8af98620ddd59f9adc1bee889128955`) had exactly five real GitHub reads and 302 passing tests. However, the read-only runner could not see the full Ruleset `bypass_actors` list. Its assertion is **`FIVE_LIVE_GETS_BYPASS_VISIBILITY_INCOMPLETE`**, not runtime proof of no bypass.
- [#341 frozen separate-read review Run 38187628606](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38187628606) (261 PASS) recorded a distinct GitHub connector projection with `bypass_actors=[]` and `current_user_can_bypass=never`. It was NOT a signed, simultaneous external observer and cannot upgrade the earlier runner's incomplete view.
- [#342 consent/audit-plan Run 38188332277](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38188332277) (335 PASS) froze future approval and audit criteria but intentionally kept writer installation, GitHub CreateRef POST and Provider API disabled.

## Independent observer trust boundary

**Proposed, NOT connected**: a distinct read-only audit principal with its own GitHub App/credential administrator, with no `contents:write`, no Actions write, and a signing key under **independent custody outside this repository and its Actions runner**. An ordinary repository-owned Actions token is not an independent auditor. GitHub's unsigned REST results do not themselves constitute signed, contemporaneous evidence, and cryptographic hash alone does not attest an observer or timestamp.

A future owner-approved trust root must explicitly pin the observer's identity, public signing key digest, version, permitted GitHub scope, retention location and key-rotation policy. The planned detached-signature scheme is Ed25519; the signing key is not generated or installed in this PR. The current source has no cryptographic signature verification for an external witness, and the manifest says so unambiguously.

## Frozen proposed receipt requirements

Each *future* independent receipt would need authenticated identity, signed capture times, the GitHub repository ID, exact `workflow_run_id`, `workflow_job_id`, HEAD and workflow file blob SHAs, exact role, ref and target commit, Ruleset ID/updated_at/enforcement/conditions/rule and **fully visible bypass** values or digests, Git ref status/body digest, observer credential scope digest, a chained previous-receipt hash, canonical receipt digest and detached signature.

Required phases: independent pre-dispatch read, independent read immediately before each writer A and B's proposed POST, server response receipts, post-run independent read and final cross-run accounting. **These are proposed receipt types, not receipts we have.** Capture-time tolerance, clock skew and receipt age bounds are all `null` and still require a *separate owner decision* before execution. No invented freshness threshold is promoted to policy.

The protocol does **not** assume that observer GET and writer POST are atomic. It requires explicit examination of the gap and the opportunity for another principal/admin to change the Ruleset or ref between samples. Even a signature-valid snapshot proves only what was observed at its time; truly unavoidable GitHub-admin mutability and non-transactional reads preclude an unqualified immutable Single-Use claim.

## Security acceptance / rejection

A future audit must reject or mark UNPROVEN: an unpinned signing key, a self-signed or reused writer identity, withheld bypass fields, unverified clock time, Ruleset/ref/HEAD changes, missing server-side ref confirmation, ambiguous POST outcomes, excessive retries/attempts and absent independent chain-of-custody. One HTTP 201 and one 422 do **not** establish an overlapping race by themselves. Failed or ambiguous POST outcomes must never be retried automatically.

Frozen trial tuple: repo `veritasfuji-japan/veritas-task4-cas-lab` ID `1414228001`, exact ref `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73`, target `9edd28eee24da559fc0ad24fd97291944acc2ed4`, Ruleset `24880024`. Four planned roles PREFLIGHT/A/B/C, planned maximum two CreateRef POSTs (at most one each A/B), retry count zero. The plan is not owner consent.

## What this PR actually changes

1. New canonical digest-pinned contract `contracts/TASK4_343_INDEPENDENT_READONLY_AUDIT_PROTOCOL_REVIEW_V1.json` with all unavailable attestations explicitly false/null.
2. Offline-only verifier `scripts/task4_343_independent_readonly_audit_review_only_v1.py` checks the exact SHA-256 of the frozen design, exact trial limits, the #342 predecessor and source write gate denial. Any **hypothetical submitted receipt** is rejected because the independent trust root and verification implementation are not installed.
3. Negative tests `tests/test_task4_343_independent_readonly_audit_review_v1.py` mutate credential independence, signature/trust-root claims, provenance, receipt fields, timing, costs, and writer authority. Every attempted unreviewed upgrade must fail closed.
4. Existing manually dispatched **offline-only** Actions workflow extends the review with this suite and JUnit, canonical report hash, source-file SHA-256, Artifact. Global/job `contents:read`, empty credentials, no new workflow or real GET.

## Remaining decision before any real cross-run CAS

**External observer feasibility must be established first**: identify a genuinely separate audit custodian/credential, where its signed witness is stored, what can be queried with its actual read-only rights, and whether capture times/bypass visibility are sufficient to meet independently agreed stop conditions. If that cannot be done, the missing runtime attestation remains unproven; the experiment must not be described as demonstrating independent bypass resistance.

No workflow merge, passing offline test or prior API permission grants authorization to execute a single GitHub CreateRef POST.

Tracking issue: https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321.
