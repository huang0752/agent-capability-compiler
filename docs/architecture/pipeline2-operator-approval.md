# Pipeline 2 Operator approval

Pipeline 2 can verify a local-development Action without exposing an approval Tool to the
agent. A live Gateway profile declares four ordered cases:

1. a `tool_call` with `action_phase: prepare`;
2. an `operator_approve` case referencing that prepare case;
3. a `tool_call` with `action_phase: commit` and `action_handle_from_case`;
4. a `tool_call` with `action_phase: status` and the same handle reference.

The profile contains no Action handle and no Operator credential. The runner receives a
runtime-only `OperatorApprovalConfig`; its `SecretRef` resolves from the supplied environment.
The endpoint is fixed to `/operator/actions/approve`, must use the exact Gateway origin, and
must be loopback. Requests do not follow redirects. The response is accepted only when it is
exactly `{\"capability_id\": <expected>, \"status\": \"approved\"}`.

The prepared handle is retained only in runner memory and is injected into commit and status
calls. Neither the handle nor a digest of it is written to `LiveGatewayReport`. The Operator
step records only secret-free provenance: mechanism, origin/path digests, case IDs, capability,
account alias, and the facts that the Operator hook ran while the approval Tool did not.

Agent Usage real-MCP verification uses an explicitly injected `TrustedOperatorApprovalHook`.
`LoopbackOperatorApprovalHook` is the built-in implementation and applies the same fixed-path,
same-origin, loopback, minimized-response, and no-redirect rules. The hook returns a concrete
non-serializable `TrustedOperatorApproval`; mappings or serialized lookalikes are rejected. An
Action requiring approval does not silently fall back to calling an approval Tool when this
hook is selected, and release verification fails closed if the real scenario does not pass.

This mechanism is intentionally limited to local development. It does not turn the in-process
Action coordinator into a production approval authority and does not replace user acceptance,
source authorization, audit, idempotency, concurrency, or durable-session requirements.
