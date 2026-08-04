# ACC MVP Progress

| Milestone | Status | Verification |
| --- | --- | --- |
| 0 — workspace and architecture | Complete | `uv lock --check`; Ruff format/lint; mypy (28 files); pytest (4 passed) |
| 1 — core models and validation | Complete | Ruff format/lint; mypy (37 files); pytest (73 passed); CLI/schema smoke |
| 2 — compiler and pack | Complete | Ruff format/lint; mypy (46 files); pytest (113 passed); deterministic/safety cases |
| 3 — generic runtime | Pending | Pending |
| 4 — eval and testkit | Pending | Pending |
| 5 — engineer skill | Pending | Pending |
| 6 — CRM acceptance | Pending | Pending |

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
