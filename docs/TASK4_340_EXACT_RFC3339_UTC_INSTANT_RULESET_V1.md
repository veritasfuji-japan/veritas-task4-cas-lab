# Task4 #340 — exact RFC3339 UTC instant comparison, no security relaxation

## Observed problem / grounded scope

The [real authenticated read-only Run 38145804543](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38145804543) completed 268 offline tests and five fixed GET calls, then failed closed with `RULESET_STATIC_RULES_DRIFT`. Artifact 11705180754's safe diagnostic reported **only** `updated_at:mismatch` (no response value recorded). Independently, the repository's connected GitHub REST ruleset returned `2026-10-11T22:00:45.379+09:00`. Thus the precise cause remains unproven. A same-instant but differently formatted RFC3339 value is a *hypothesis*, not yet proof.

## Single invariant

A Ruleset's `updated_at` may differ *lexically* only when both values parse as valid explicit-timezone RFC3339 timestamps and represent the **exact same UTC instant at microsecond precision**.

This PR **does not** accept timestamps that are merely close, truncate milliseconds, shift time zones without offset correctness, fill in missing offsets, or tolerate actual Ruleset updates.

For example, frozen `2026-10-11T22:00:45.379+09:00` equals `2026-10-11T13:00:45.379Z`. It does **not** equal `2026-10-11T13:00:45Z` (fraction lost) or `2026-10-11T13:00:45.379001Z` (one microsecond later).

## Change boundaries

- Add one strict RFC3339 parser with explicit `Z` or numeric offset, calendar validation, max six fractional digits, and UTC normalization; accepts zero tolerance.
- The existing `static_ruleset_drift_fields` comparison retains all 8 security-critical checks unchanged for `id`, `name`, `target`, `source_type`, `enforcement`, `conditions`, `rules`. Only `updated_at` uses identical-UTC-instant comparison.
- The #339 failure report stays hashed and FAIL_CLOSED. If the timestamp genuinely changed or is malformed, it still records `updated_at:mismatch`, without leaking the raw value.
- A successful read-only report explicitly marks `ruleset_updated_at_exact_instant_verified:true` and `ruleset_updated_at_text_format_differs`. This is only an observation and **never** owner consent, an authorization token or a GitHub CAS proof.
- New mock-only tests cover equivalent timezones, 1-microsecond mismatch, missing offset, bad date, invalid UTC offset, missing or changed other Ruleset fields, bypass visibility and absence of POST.
- The existing only-owner, manual-only, `main`-only read-only workflow runs the new tests before the same five GitHub GET calls. It retains **global/job `permissions: contents: read`**, scoped ephemeral `${{ github.token }}`, no automatic triggers, no retries, and `upload-artifact if: always()`. No runnable write workflow added and no Provider API call.

## Next evidence after reviewed merge, not in this PR

1. Run `task4-338-live-authenticated-readonly-preflight-manual.yml` **once** on `main`, then check Run/Job IDs, the new HEAD, JUnit, artifact digest, response status/body digests and visibility classifications.
2. If `updated_at` is the same UTC instant, #340 should clear this gate. Any other drift or withheld bypass metadata must remain **denial or incomplete**; a green read-only run is **not** a writer authorization.
3. No GitHub CreateRef POST, Provider POST, banking side effects, or privileged RuleSet modification is authorized by this work.

Research issue: https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321.
