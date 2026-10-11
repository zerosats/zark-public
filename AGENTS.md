# Working on Zark

Organize source by responsibility. Keep substantial operations in focused modules
and small related helpers beside their callers. File and function lengths are
review signals, not quotas: prefer roughly 200–400 lines per production module
and examine modules above 500 without fragmenting cohesive logic.

Use explicit module boundaries and descriptive names. Avoid broad utility modules,
unnecessary public visibility, wildcard imports when practical, and abstractions
whose only purpose is reducing line count. Document why security-sensitive ordering
or checks are required. Keep workflow orchestration readable in one place.

Preserve canonical bytes, public APIs, persisted formats, exact retries, lock
lifetimes, commit-before-response, and recovery-before-acknowledgement during
organizational refactors. Never replace constraints or validation with assumptions.
Circuit refactors require checking compiled artifacts and deployment implications.

Remove obsolete paths and redundant tests only after checking their consumers.
Retain distinct adversarial, crash, replay and recovery coverage. Existing wallet
state and pending operations are not disposable test fixtures. Use isolated
synthetic fixtures under ignored `work/` and never commit secrets or artifacts.

Use the pinned Rust toolchain and locked dependencies. `scripts/check-local.sh`
provides Rust checks; `sh apps/desktop/test.sh` runs desktop tests. Real-proof and
Bitcoin tests require explicit tools/configuration and are not implied by a normal
test pass. Run checks appropriate to the change and report unavailable validation.

Keep README as a concise description of the current research prototype and its
basic test commands. Do not add overlapping protocol plans or qualification
reports unless explicitly requested.
