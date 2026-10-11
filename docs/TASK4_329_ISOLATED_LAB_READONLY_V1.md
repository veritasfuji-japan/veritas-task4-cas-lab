# Task4 #329 — Isolated GitHub CAS lab: READ-ONLY preparation

## Scope and current safety boundary

Lab repo: \`veritasfuji-japan/veritas-task4-cas-lab\` (**PRIVATE** at initial verification), lab initialized main commit \`058cae0a86fdceafdab8408c225f6059c40feb2b\`.

Source benchmark: \`veritasfuji-japan/rcc-revas-veritas-benchmark\`, source merged #328 main \`e3365d35054c06df09a37f3f4926bbe6c2fdba06\`.

This PR adds ONLY immutable test scope, a non-network offline Python plan, adversarial fixture tests, and a **manual-only, read-only** GitHub Actions workflow. No actual trial ref, CreateRef request, Provider API request, credential, runner dispatch, repository permission modification or real bank side effect is authorized or performed. The normal feature branch/PR is the ONLY repository mutation from preparing this draft.

The canonical planned trial ref is:

\`refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73\`

Its suffix is the leading 32 hex characters of the SHA-256 canonical frozen scope. The ref is a **proposal only**; it does not exist as a lease.

## Why manual-only CI?

The newly created lab is **private**, and its GitHub Actions included/billable minutes and billing cap have not been verified. Therefore the workflow is \`workflow_dispatch\` **only**, never triggered by \`pull_request\` or \`push\`. It cannot be manually dispatched until merged into the default branch; **do not run until private Actions consumption is explicitly accepted**. Workflow requests \`permissions: contents: read\`, checks out exact main \`github.sha\`, does not persist checkout credentials, uses no \`secrets.*\`, and does not expose any GitHub or OpenAI token to the test process.

\`pytest==9.1.1\` and \`python==3.11.16\` are pinned for repeatability. Running the workflow would still use GitHub-hosted compute minutes and package download bandwidth, so check billing first. The only resulting Artifact is a plan, JUnit, SHA256, and audit logs. **No proof of real cross-run CAS follows from this preflight**, even if all tests pass.

## Proposed protocol for a *later, separately authorized* GitHub-only experiment

1. **Independent approval gate:** owner supplies a frozen lab repository/branch SHA, exact single test ref name, a GitHub ref-write permission scope, number of manual runs (A+B+optional read-only C), and allowed runner-minute budget. This approval is **only** for GitHub test-ref metadata, not Provider API or live financial operations.
2. **Threat model review:** before any write workflow, inspect the repo's Rulesets and collaborators, actor permissions, audit log access, ref deletion and force-push possibilities, and namespace collisions. \`contents:write\` is repo-wide permission in the GitHub token and is **not inherently limited by the exact proposed ref prefix**. Any executable write workflow must be pinned and reviewed on the default branch and have no untrusted PR checkout.
3. **Real remote requests — when authorized separately:** two distinct GitHub Actions run IDs on distinct GitHub-hosted runners send **one** \`POST /repos/{owner}/{repo}/git/refs\` attempt to create the identical planned ref with the frozen lab main SHA. Check HTTP 201 vs conflict/422 response **content** and verify remote ref identity. A generic 422 alone is not duplicate proof. No retry after timeout/UNKNOWN.
4. **Third independent check:** after both runs, a new main-branch run only *GET*s the ref and proves it persisted after job restart, without attempting CreateRef. Record timestamp, run/job IDs, exact HEAD, request body SHA, response code, sanitized response JSON SHA, observed ref SHA, JUnit and Artifact ZIP SHA-256.
5. **Immutability gap:** even a successful real GitHub atomic CreateRef test cannot attest that an admin cannot delete/move the ref and reuse it. The ref should not be deleted as part of a risky test; instead inspect configured protections and identify unresolved admin bypass. For production authorization, seek an independently administered non-resettable consume-before-send backend.

### Absolute prohibitions

Never use a Provider credential, OpenAI sender/POST, authenticated banking endpoint, paid model trial, historical consumed approval, implicit GitHub Environment protection or \`concurrency\` as evidence of durable use-once. Offline scripted AgentDojo/RCC/VERITAS scores from #323-#328 are unchanged; no new genuine model Utility or Injection Success has been measured.

## Expected proof statuses

- \`#329_LAB_REPOSITORY_BOOTSTRAPPED\` — VERIFIED: private repository and README main were confirmed
- \`#329_READ_ONLY_CODE_PREPARED\` — PREPARATION: manual-only workflow, fixture scope, and negative tests in Draft PR
- \`#329_LOCAL_TESTS_GREEN\` — **NOT PROVEN** until an actual test run is executed and independently inspected
- \`#329_GITHUB_REAL_REF_CREATED\` — **FALSE**, none attempted
- \`#329_DISTINCT_ACTIONS_RUNS_CAS\` — **NOT PROVEN**, none dispatched
- \`#329_REF_IMMUTABILITY\` — **NOT PROVEN**
- \`#329_PROVIDER_API_AUTHORIZED\` — **FALSE**

Related tracking: [source benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321). New authenticated experiments require their own explicit authorization; this document is not a grant.
