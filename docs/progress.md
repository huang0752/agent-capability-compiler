# ACC MVP Progress

| Milestone | Status | Verification |
| --- | --- | --- |
| 0 — workspace and architecture | Complete | `uv lock --check`; Ruff format/lint; mypy (28 files); pytest (4 passed) |
| 1 — core models and validation | Pending | Pending |
| 2 — compiler and pack | Pending | Pending |
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
