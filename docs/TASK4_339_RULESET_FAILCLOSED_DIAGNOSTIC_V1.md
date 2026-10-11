# Task4 #339 — fail-closed, field-scoped Ruleset diagnostic evidence

## The observed failure

Real authenticated read-only #338 [Run 38145112044](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38145112044) and Job 114486716879 completed its offline suite (247 PASS), then stopped after five HTTP results during exact Ruleset validation with `Denied: RULESET_STATIC_RULES_DRIFT`. The failed run's artifact (11703779804; SHA-256 `fbaebbda9d214e8059f87ea3e8da02f1310576c0346834a6744cca52d928b320`) has **no real GET JSON report**.

The exact mismatch is **NOT YET KNOWN**. Do not change the Ruleset or broaden token access based on the generic exception.

## One invariant

A failed or incomplete authenticated GitHub GET preflight **must produce safe, reproducible negative evidence**, without transforming a failed check into approval or leaking the token / raw body.

#339 leaves intact:

- The manual #338 GitHub Actions job, only the owner and main, first attempt, **global and job-level `contents:read`**, ephemeral `${{ github.token }}` only in the GET step.
- EXACT five HTTPS GET paths to `api.github.com`, no retry, no redirects, no POST.
- Frozen Ruleset 24880024: `id,name,target,source_type,enforcement,updated_at,conditions,rules` **all must match exactly**. Unknown or omitted static field remains a failed preflight.
- The `bypass_actors` and `current_user_can_bypass` fields are never inferred from a missing field. Missing bypass metadata means **incomplete visibility**, not verified no-bypass.
- Old #330 source write gate disabled, no executable CreateRef workflow, no Provider token or API.

## What changed

1. `static_ruleset_drift_fields` identifies each missing or mismatched security-critical **field name** (`source_type:missing` for example), not its value. No assumption about the cause of the failed Run.
2. `run` now captures denied GET or validation events with `FAIL_CLOSED`, a known failure code, count of completed requests, five fixed endpoint paths, per-response HTTP status and SHA-256 hash. The raw response and bearer token are never written to Artifact.
3. `main` writes a canonical JSON report including its own SHA-256 **before exiting 1 on denied verification**; the workflow remains FAIL when security checks fail.
4. An independent `if: always()` step computes the file SHA-256 list even when the authenticated GET step exits 1. The existing Artifact upload also remains `if: always()`.
5. A new **offline-only** negative test module rejects missing/changed rule fields, 403, bypass actors, partial transport error, and unsafe claims.

## Next check after merge (NOT executed by this PR)

Trigger the existing [manual #338 workflow](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/workflows/task4-338-live-authenticated-readonly-preflight-manual.yml) on `main` **once**. Compare the new Run's main SHA, Job ID, JUnit, JSON `failure_code` and `ruleset_static_drift_fields`, real HTTP statuses, Artifact ZIP digest and individual file digests. Even if the Run is green, the read-only observation does not issue any write authorization.

**Classification:** `#339_DRAFT_FAILCLOSED_EVIDENCE_ONLY / ZERO_CREATE_REF_POST / PROVIDER_DENY / REAL_GITHUB_CAS_UNPROVEN`.
