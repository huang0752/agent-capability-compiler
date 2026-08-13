# Production loopback operator approval

The production operator endpoint is enabled only by both
`--production-actions` and `--production-action-operator-approval`. Its
credential comes from `--production-action-operator-secret-ref`, uses the
dedicated `X-ACC-Production-Operator-Authorization` header, and must not reuse
the Action Store, Vault, Approval Authority, audit, or development operator
SecretRef or secret value.

The Gateway must listen on loopback and must already use the durable SQLite
Action Store, Approval Authority, Action audit, and encrypted Session Vault.
The development and production operator modes are mutually exclusive.

The strict request body is at most 1 KiB:

```json
{
  "action_handle": "one-time prepared handle",
  "decision_id": "operator decision identifier",
  "approver_id": "authenticated operator identifier",
  "expires_in_seconds": 30
}
```

The trusted endpoint resolves only a handle previously observed during
`prepare`, recovers the session through the Vault's keyed session digest,
obtains the Coordinator binding, issues a durable approval, and consumes it in
`coordinator.approve`. The response contains only `capability_id` and `status`;
it contains no Action handle, approval grant, binding, or credential. The
durable Action audit records `decision_id` through the normal Coordinator
approval span.

## Restart boundary

The pending operator registry is intentionally process-local. It stores only
the SHA-256 Action-handle digest, a keyed Vault session digest, and a monotonic
expiry. It stores neither raw handle nor raw session identifier. After Gateway
restart, an Action that was prepared but not approved must be prepared again
before this endpoint will approve it. Durable Action status remains available,
but the endpoint never performs an unbound store lookup supplied only by an
operator request.
