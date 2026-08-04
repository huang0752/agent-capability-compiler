# ACC MVP Progress

| Milestone | Status | Verification |
| --- | --- | --- |
| 0 — workspace and architecture | Complete | `uv lock --check`; Ruff format/lint; mypy (28 files); pytest (4 passed) |
| 1 — core models and validation | Complete | Ruff format/lint; mypy (37 files); pytest (73 passed); CLI/schema smoke |
| 2 — compiler and pack | Complete | Ruff format/lint; mypy (46 files); pytest (113 passed); deterministic/safety cases |
| 3 — generic runtime | Complete | Ruff format/lint; mypy (56 files); pytest (182 passed); real MCP stdio handshake |
| 4 — eval and testkit | Complete | Ruff format/lint; mypy (77 files); pytest (252 passed); runtime and pack/MCP E2E CLI |
| 5 — engineer skill | Complete | skill-creator validation; Ruff/mypy; pytest (274 passed); independent Phase 0–3 forward test |
| 6 — CRM acceptance | Complete | ACC gates 9/9 each; source 34 passed; repository 281 passed; deterministic Pack and real MCP stdio |

This file records fresh command evidence at each milestone. A status changes to complete only after its focused tests, the full test suite, lint, type checking, diff review, and milestone commit have succeeded.

## Verification log

### 2026-08-04 — Milestone 0

- `uv sync --frozen --all-packages --group dev`
- `uv lock --check`
- `uv run --frozen ruff format --check .` — 38 files already formatted
- `uv run --frozen ruff check .` — all checks passed
- `uv run --frozen mypy packages tests` — 28 source files, no issues
- `uv run --frozen pytest` — 4 passed

### 2026-08-04 — Milestone 1

- TDD red evidence: model tests initially 25 failed; IO tests initially 19 failed; CLI tests initially 7 failed; project validation initially failed import
- `uv run --frozen acc schema --output schemas --json` — six Draft 2020-12 schemas exported
- `uv run --frozen acc --help` — `init`, `doctor`, `schema`, and `validate` registered
- `uv run --frozen ruff format --check .` — 47 files already formatted
- `uv run --frozen ruff check .` — all checks passed
- `uv run --frozen mypy packages tests` — 37 source files, no issues
- `uv run --frozen pytest` — 73 passed

### 2026-08-04 — Milestone 2

- TDD red evidence: compiler API missing; Pack API missing; analysis APIs missing; M2 CLI commands missing; protected output and nested-source cases reproduced
- `uv run --frozen ruff format --check .` — 56 files already formatted
- `uv run --frozen ruff check .` — all checks passed
- `uv run --frozen mypy packages tests` — 46 source files, no issues
- `uv run --frozen pytest` — 113 passed
- Pack tests build identical archives twice and verify lock coverage, traversal, symlink, duplicate, unknown-entry, checksum, size, and protected-output rejection
- `uv run --frozen acc --help` — `compile`, `coverage`, `diff`, `freeze`, and `pack` registered

### 2026-08-04 — Milestone 3

- TDD red evidence: runtime loader, credentials, ten workflow actions, HTTP provider, policy enforcement, MCP adapter, and `run` command were each introduced from failing tests
- `uv run acc schema --output schemas --json` — refreshed project and operation schemas for strict environment references and query mappings
- `uv run ruff format --check packages tests` — 56 files already formatted
- `uv run ruff check packages tests` — all checks passed
- `uv run mypy packages tests` — 56 source files, no issues
- `uv run pytest -q` — 182 passed
- The MCP integration test launches `acc run <pack>`, completes an SDK stdio handshake, and lists the compiled capability with empty stderr
- Runtime tests cover verified pack loading, stable errors, secret redaction, all ten workflow actions, schema checks, fixed-origin GET/HEAD requests, bounded responses, tenant/scope policy, output filtering, and protocol-safe errors

### 2026-08-04 — Milestone 4

- TDD red evidence: contract/runtime Eval APIs, Adapter SDK contracts, Fake REST transport, faults, assertions, recorder interoperability, adapter scaffolding, and all three `acc test` suites began from focused failing tests
- `uv lock --check` — lockfile is current after direct PyYAML/jsonschema dependencies
- `uv run ruff format --check packages tests` — 77 files already formatted
- `uv run ruff check packages tests` — all checks passed
- `uv run mypy packages tests` — 77 source files, no issues
- `uv run pytest -q` — 252 passed
- `acc test contract --json` statically checks bindings, schemas, operation dependencies, positive cases, and permission-negative coverage
- `acc test runtime --json` executes both expected-success and expected-403 cases against a real local HTTP boundary; `acc test e2e --json` additionally verifies a generated pack and calls through the MCP adapter
- Testkit tests cover FastAPI and no-socket transports, fixture loading, deterministic 403/404/timeout/oversize faults, call recording, MCP stdio client cleanup, output/error/forbidden-field assertions, and domain-neutral example data
- Adapter SDK tests cover strict GET/HEAD contracts, health metadata, safe paths, exact route registration, write-route rejection, YAML loading, generated scaffolds, and a deployable domain-neutral fake adapter

### 2026-08-04 — Milestone 5

- Initialized `skills/acc-engineer` with the canonical `skill-creator` script and generated deterministic `agents/openai.yaml` metadata
- Implemented the platform-neutral `HARNESS.md`, nine phase guides, eight templates, focused schema/example references, and five standalone JSON safety scripts
- Added thin Codex and Claude Code installers/commands that delegate to the single Skill/Harness method and refuse overwrite
- `quick_validate.py skills/acc-engineer` — `Skill is valid!`
- `uv run pytest tests/unit/skill -q` — 22 passed
- `uv run ruff format --check .` — 116 files already formatted
- `uv run ruff check .` — all checks passed
- `uv run mypy packages tests skills/acc-engineer/scripts` — 88 source files, no issues
- `uv run pytest -q` — 274 passed
- Independent minimal-context forward test completed Phases 0–3 against an unfamiliar read-only adapter package, produced a source-stable blocked plan, and correctly refused implementation without user-goal/auth/scope/tenant evidence
- Forward-test findings were incorporated: explicit `acc init` cold start, Python 3 invocation, canonical macOS paths, preflight/coverage-baseline templates, conditional permission-negative/empty scenarios, blocked-plan semantics, and whole-file evidence digest documentation

### 2026-08-04 — Milestone 6

- Applied `skills/acc-engineer` through Preflight, Analyze, Model, Plan, Implement, Validate, Test, Refine, and Handoff against an independent synthetic FastAPI CRM
- Source system: six GET-only routes, Bearer auth, four read scopes, token/request tenant equality, strict response models, synthetic A/B tenant data, runtime OpenAPI checks, and 34 passing isolated tests
- ACC project: six frozen evidence-bound Operations, three Policies, nine Evals, and three business capabilities; `get_customer_context` composes customer, contacts, followups, and todos
- `acc validate --json` and `acc compile --check --json` passed; Coverage has no orphans or missing eval/permission-negative coverage and retains two documented low-risk one-interface heuristics
- Contract, Runtime, and E2E CLI suites each passed 9/9 against the real local CRM HTTP boundary
- E2E tests verify policy-before-public-schema validation, masked contact email, omitted tenant fields, stable 404/403/timeout/oversize errors, SecretRef isolation, and real MCP stdio list/call
- Two CLI-built Packs were byte-identical with SHA-256 `d6670760bc1d690f6e34e57cc9dff029c258f91a4912486fd7032345724fc6ae`
- Final source snapshot matched the Preflight digest with zero source changes; formal Operations without Evidence: 0; invented endpoints: 0; runtime LLM calls: 0
- `uv lock --check`; Ruff format/lint; strict mypy; repository `pytest -q` — 281 passed
