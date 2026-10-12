# Task4 #341 — separate read-path Ruleset bypass evidence freeze (OFFLINE ONLY)

## Evidence that exists

1. **Runner observation**: authenticated read-only GitHub Actions [Run 38186765875, Job 114610648509](https://github.com/veritasfuji-japan/veritas-task4-cas-lab/actions/runs/38186765875), `main` SHA `cd1d137da8af98620ddd59f9adc1bee889128955`. 302/302 offline tests passed and exactly five HTTPS GET requests were reported. Artifact `11719338461`, ZIP SHA-256 `51e4af5d773b2c158cc128b45b1bb2501980d84c6e10b37aae4526be0c550a34`, contains the read-only JSON report, whose stored byte SHA-256 and canonical SHA-256 are also frozen. Its Ruleset GET returned HTTP 200 and its strict static fields passed; **`bypass_actors` was not visible to the read-only runner token**.
2. **Separate observer snapshot**: a subsequent connected GitHub REST GET `/repos/veritasfuji-japan/veritas-task4-cas-lab/rulesets/24880024` showed Ruleset active, exact ref condition, deletion / non_fast_forward / update rules, `updated_at=2026-10-11T22:00:45.379+09:00`, `bypass_actors=[]` and `current_user_can_bypass=never`. Its field projection is transcribed into the frozen contract.

These two sources were obtained by **different read paths**, but the second is not a signed audit attestation, its exact observation clock-time and token scope are unverified, and it was **not simultaneous** with the runner. The original Action did not receive the bypass list, and the source runner's full Ruleset HTTP body is **not recoverable** from its body digest alone. Consequently there is **no way to cryptographically cross-equal the complete raw Ruleset HTTP body**. Do not report independent live-by-run bypass proof.

## What is implemented

- `contracts/TASK4_341_SEPARATE_READ_BYPASS_EVIDENCE_FREEZE_V1.json` stores exact verified Run/Job/Artifact identifiers, the complete runner report, its SHA-256 hashes and separate Ruleset field projection, plus explicit unavailable-attestation indicators.
- `scripts/task4_341_separate_read_bypass_evidence_review_only_v1.py` validates the frozen original report's canonical SHA-256 and reconstructed file byte SHA-256 against the independently downloaded Artifact; verifies exact source Run ID/HEAD/status/ref, all Bypass claims and all fields of the transcribed separate Ruleset projection; and checks existing source and workflow writer gates stay OFF.
- The verifier is **purely offline**, no GET or POST client, no token, no Provider calls and no real GitHub execution effect.
- Negative tests reject evidence digest mutation, changed Ruleset fields, false bypass claims, minted provenance/signedness, GitHub writing, and Provider authorization.
- An existing manually invoked offline-review workflow runs these tests and emits a SHA-256 hashed report. No new Actions workflow or access scope is created.

## Strict result taxonomy

- **PASS (offline snapshot consistency):** the two records share a frozen Ruleset identity, last-updated instant and expected static protection fields and the separate read path observed empty bypass actors.
- **NOT PROVEN (runtime bypass):** the Action itself could not see `bypass_actors`. The second read had another auth scope and occurred at an unattested time, and the source report does not include the full Ruleset body. There is no same-principal, same-time independently signed attestation.
- **NOT PROVEN (authority):** No real GitHub cross-run CreateRef CAS, independent admin custody, non-resettable single-use, real bank/model Provider execution, or owner SHA-scoped ref-write approval.

Do NOT change the Ruleset or issue `contents:write` just to make the read-only status green. Stronger evidence would require separately scoped independent authorization/audit, including true runtime attestation and no opportunity for ref/ruleset reset.

Research tracking: https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321.
