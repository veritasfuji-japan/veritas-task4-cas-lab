# veritas-task4-cas-lab

**Isolated, private GitHub research lab. No live Provider actions.**

This repository is a separate test-only space for investigating whether a **single exact Git ref** can be created at most once across independent GitHub Actions runs. It does not connect to VERITAS production authorities, an actual bank or any OpenAI model API.

## Phase #329: read-only preparation

The current [read-only scope and experiment plan](docs/TASK4_329_ISOLATED_LAB_READONLY_V1.md) contains the proposed exact ref name, negative tests and a **manual-only** CI workflow.

- No GitHub test lease ref has been created.
- No real GitHub CreateRef requests have been made.
- No real GitHub Actions two-run CAS result or immutable admin custody is established.
- No model Provider API key, sender, execution approval or expense is authorized.
- The workflow is **manual-only** because billing/allowance for private-repository Actions minutes has not been verified; no automatic PR/push CI.

Before any real GitHub ref-write experiment, require separate explicit permission for one fixed lab ref, test-run count, GitHub write-token scope, budget and evidence collection. Never infer that a CreateRef 201/422 pair proves a non-resettable, independently administered authority.

Source tracking: [benchmark Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
