# Focused examples

- Start successful cases from `../../templates/eval.yaml`.
- Use `permission-negative-eval.yaml` as the paired authorization failure case when a Capability policy declares scopes or `tenant_mode: required`.

Keep identifiers aligned across files:

| Reference | Must equal |
|---|---|
| Capability workflow `call.operation` | Operation `id` |
| Capability `policy` | Policy `id` |
| Capability `evals[]` | each Eval `id` |
| Eval `capability` | Capability `id` |
| Eval `expected_calls[].operation` | invoked Operation `id` |

The negative example expects denial before an upstream call, so `expected_calls` is empty and no fake credential or production fixture is needed.
