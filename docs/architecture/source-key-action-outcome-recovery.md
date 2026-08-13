# Source-key Action outcome recovery

ACC can recover an ambiguous source-key Action outcome only through a compiler-proven,
read-only source ledger query. The mutation is never replayed.

A `status_query` used with `source_key` idempotency declares exactly one
`runtime_idempotency_key` request binding plus `success_pointer` and canonical,
sorted `success_values`. The compiler proves that the binding target accepts a
non-empty string, every other required query input comes from sealed Action input or
public prepared preview, the success pointer is guaranteed by the Read Operation
output schema, and every success value satisfies that field schema. These recovery
fields are forbidden for non-source-key strategies; existing `state_idempotent`
status-query behavior remains unchanged.

After commit begins, transport failure, cancellation, or failure to durably record the
result leaves the Action in `OUTCOME_UNKNOWN`. A later `status()` unseals the
Runtime-generated idempotency key from the trusted Action Store and calls only the
declared Read Operation. A proven success result is policy-filtered, validated against
the Action output schema, and compare-and-swap persisted as
`OUTCOME_UNKNOWN -> SUCCEEDED`. Pending, not-found, transport failure, or an
unrecognized source status leaves the record unknown. Concurrent recovery has one
CAS winner and never invokes the mutation Operation.

The raw idempotency key remains inside trusted execution values. It is not returned in
Action status, diagnostics, audit events, or object representations. Durable restart
recovery therefore depends on preserving the authenticated Action Store and its keying
material.
