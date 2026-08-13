# Production Action Adapter SDK

The Adapter SDK keeps the existing read surface unchanged: `AdapterOperation`
accepts only `GET` and `HEAD`, and read handlers are still installed with
`register_operation`.

A mutation is a different contract type, `AdapterActionOperation`, and is
installed only with `register_action`. Every Action must declare all of these
invariants:

- `idempotency.mode: source_key`, with a Runtime-owned header or JSON-body
  target;
- `concurrency.mode: required`, including the preview token source and the
  commit precondition target;
- `transactional_outcome: true`;
- `authorization: source_revalidated`;
- bounded request and response sizes.

The server rejects missing idempotency or concurrency controls before invoking
the handler, enforces the byte limits, and requires a `source_authorizer`
dependency for every registered Action. Read registration cannot install an
Action, and Action registration cannot install a read operation.

## Meaning of transactional outcome

`transactional_outcome: true` is a source implementation claim, not a promise
created by HTTP middleware. The Action implementation must atomically persist:

1. the source idempotency-key claim and canonical request digest;
2. the optimistic version comparison;
3. the business mutation; and
4. the durable command outcome returned by later status queries.

Those writes must commit in the same source database transaction. A Sidecar
that first mutates an upstream HTTP API and later records the outcome in its
own database does **not** satisfy this contract: process or network failure
between those writes leaves an unrecoverable ambiguity.

On a repeated idempotency key, the source must return the previously committed
outcome only when the canonical request digest is identical. Reusing the key
with different input must fail. A stale concurrency token must fail without a
business mutation or outcome row.

## Authorization boundary

`source_authorizer` must revalidate the source credential and current business
permission on every Action request. ACC approval authorizes the prepared Agent
request; it does not replace source authentication, tenant isolation, or RBAC.
Adapters must not trust caller-supplied identity or tenant fields.

## Minimal endpoint shape

A production Sidecar normally exposes a preview/status read and one Action:

```yaml
operations:
  - id: records.get
    method: GET
    path: /records/{record_id}
    summary: Read record and current version
  - id: records.close
    method: POST
    path: /records/{record_id}/close
    summary: Close record atomically
    safety:
      idempotency:
        mode: source_key
        target: {kind: header, name: Idempotency-Key}
      concurrency:
        mode: required
        token: {kind: response_header, name: ETag}
        precondition: {kind: header, name: If-Match}
      transactional_outcome: true
      authorization: source_revalidated
      max_request_bytes: 65536
      max_response_bytes: 65536
```

The corresponding ACC Operation uses the same injection targets and cites
implementation and concurrency tests as Action-semantic evidence. Merely
declaring this Adapter contract is not sufficient evidence for production
compilation.
