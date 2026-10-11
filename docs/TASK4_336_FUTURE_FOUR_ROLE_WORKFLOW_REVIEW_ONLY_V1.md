# Task4 #336 — final future workflow and least-privilege boundary review (STAGED ONLY)

## One central invariant

A proposed workflow containing a `contents:write` job **cannot become executable** from a review-only PR or a previous GitHub Actions success. This PR stages a three-job/four-run future design **outside** `.github/workflows` and with all jobs unconditionally disabled. There is **no real GitHub ref writer, Provider credential, API POST, effect, or model scoring** in #336.

## What is already verified

- Public isolated repo `veritasfuji-japan/veritas-task4-cas-lab`, #335 main reviewed as `dd047ed08b556fbd2505a6d6f93d5ed715dc3ce8`.
- Ruleset [24880024](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/rules/24880024) active, target exactly `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73`, bypass list empty, `deletion`, `non_fast_forward`, `update` set. `current_user_can_bypass=never` applied to the observed user, **not** proof that an admin can never alter/disable the ruleset. The ruleset must be independently re-fetched immediately before future authorized requests.
- Proposed reference `refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73` was not found (404) on most recent read; old 404 is **not** a future runtime precondition and may reflect access issues. Existing target commit `9edd28eee24da559fc0ad24fd97291944acc2ed4` was independently found at review time.
- Last [#335 GitHub Actions run](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38142883613) succeeded 107/107; its output proves only the offline validation.
- #330 `REAL_GITHUB_WRITE_SOURCE_GATE=False`, `APPROVED_WORKFLOW_HEAD_SHA=None`, `LIVE_PROVIDER_DISPATCH_ALLOWED=False` stay **unchanged**. #333 and #335 guards still require exactly four manual read-only active workflows and zero writer workflows.

## Staged workflow layout (NOT executable)

The file `docs/templates/task4-336-four-role-create-ref-STAGED-NOT-INSTALLED.yml` is a **documented future draft**, not GitHub Actions itself.

| Job in staged template | Proposed permission | Roles in distinct future Runs | Current |
| --- | --- | --- | --- |
| `readonly-preflight` | `contents:read` | PRECHECK / PREFLIGHT | `if: false`, refusal-only |
| `writer-once` | `contents:write` | A, B: one run each | `if: false`, refusal-only |
| `readonly-audit` | `contents:read` | C | `if: false`, refusal-only |

**Four separate future workflow runs**, not four jobs in one run: PREFLIGHT, A, B, C. This template contains three job definitions because A and B would invoke the same writer job in separate runs. It is a nonfunctional structure: there are no GitHub HTTP request implementations inside it.

The template has no PR/push trigger, no exposed Provider key, no unpinned actions, no persisted checkout credential, and no actual CreateRef call. Each staged job fails with exit code 78 even if someone removes its `if: false` guard; movement or modification still requires another reviewed PR.

Do **not** configure a GitHub Actions `concurrency` key that serializes A and B. Two distinct Actions runs can execute sequentially, however: a **race** is only proven by separately recorded overlapping request intervals with trusted timestamps; otherwise the outcome shows distinct-run uniqueness, not contention.

## Required activation sequence — separately authorized, not included

1. Create a distinct explicit owner-approved PR to install the future workflow under `.github/workflows/task4-330-authorized-create-ref.yml`, with genuinely implemented independent preflight and readback, fail-closed REST/Ruleset/issuer checks, and a one-POST no-retry writer. **Nothing in this PR authorizes that PR to be merged or run.**
2. Keep all write paths inert while reviewing the final proposed code. Obtain the final executable commit SHA **after merge**, then separately authorize exactly that SHA and workflow path; embedding its own final commit SHA in the same commit creates a self-referential pinning problem. An externally issued approval must not be presumed from an environment variable controlled by the same repository admin.
3. Confirm GitHub plan/runner costs and storage, runner allowance where applicable, permissions `contents:write` (repo-wide token; not restricted to this ref by the GitHub token itself), ruleset administrative custody, no bypass, and exact object/ref access.
4. Prepare PREFLIGHT run read-only, then separately approved writer Run A and B (at most one POST per run, total two). No automatic GitHub retry/redispatch, client retry, or replay after unknown status. Record original body SHA, status/body digest, run ID, job ID, checked-out commit, workflow SHA and actual timestamps.
5. Launch an independent read-only C run to query the exact ref and independently inspect A/B metadata and receipts. A 422 alone is not proof of duplicate. Status 201 alone is not proof of immutable cross-host lease. Never delete/recreate the ref as part of the proof.
6. Treat all results as **GitHub-lab research only**, not as independent production permission or Provider API budget/authorization. A repository owner able to edit rules remains a trusted actor rather than an independently controlled irreversible ledger.

Even four successful roles do not prove independent admin custody, durable non-resettable consumption or live OpenAI utility.

### Engineering limits under review (NOT spending approval)

PREFLIGHT, A, B, C = at most four hosted runs, `ubuntu-24.04`, 8-minute job timeout each (proposed 32 runner-minutes ceiling), two CreateRef POST attempts total, no retries. The timeout is not guaranteed to cap all bills or side effects. Public standard GitHub-hosted Actions minutes are typically free, but additional storage and configuration-specific charges remain separate. New specific consent is mandatory.

**Result classification for #336:** `STAGED_WORKFLOW_REVIEW_ONLY / ACTIVE_WRITER_ABSENT / ACTUAL_POSTS_ZERO / REAL_CAS_UNPROVEN / PROVIDER_DENY`.

Tracking: [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
