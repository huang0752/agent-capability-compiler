# Focused examples

- Start successful cases from `../../templates/eval.yaml`.
- Use `permission-negative-eval.yaml` as the paired authorization failure case when a Capability policy declares scopes or `tenant_mode: required`.
- Use `server-serialized-transition.yaml` only when implementation/test Evidence proves that the source serializes the allowed-state transition. Replace every Evidence sentinel; the example intentionally fails strict validation before replacement.
- Use `evidence-derived-intent-plan.yaml` to review how the Coding Agent keeps useful single-route intents, merges only equivalent state transitions, and leaves an unsafe Action blocked. Its three materializable intents are an Evidence-derived result, not a quota.

Keep identifiers aligned across files:

| Reference | Must equal |
|---|---|
| Capability workflow `call.operation` | Operation `id` |
| Capability `policy` | Policy `id` |
| Capability `evals[]` | each Eval `id` |
| Eval `capability` | Capability `id` |
| Eval `expected_calls[].operation` | invoked Operation `id` |

The negative example expects denial before an upstream call, so `expected_calls` is empty and no fake credential or production fixture is needed.
