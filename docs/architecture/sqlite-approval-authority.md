# SQLite external Approval Authority

`SQLiteApprovalAuthority` is the minimal platform-neutral production reference for an
operator-owned Action approval service. It implements the Runtime's read-side
`ApprovalAuthority.verify()` protocol, while `issue()`, `revoke()`, and `decision()` are trusted
operator-side methods. They must never be exposed as MCP tools or made callable by the Agent.

## Trust topology

Run approval collection in a process or service controlled by the operator. After a human or
policy engine authorizes a prepared Action, that service obtains the trusted
`ApprovalBinding` from the Gateway host and calls `issue()`. It passes the returned opaque handle
to the Gateway over a separately authenticated operator channel. The Action coordinator only
accepts the handle when every binding field still matches the prepared record.

The authority database may be opened by the approval service and the Gateway verifier at the
same time. SQLite `BEGIN IMMEDIATE` transactions serialize consumption, so exactly one verifier
can consume a decision, including across processes. Do not place the database on a network file
system whose locking or durability semantics differ from local SQLite.

## Persisted evidence and secret handling

Each authenticated row records:

- unique operator `decision_id` and `approver_id`;
- all fields of `ApprovalBinding`, including the prepared Action expiry;
- approval expiry and approved, consumed, or revoked timestamps;
- the revoking operator identity when applicable.

The raw approval handle is never stored; its SHA-256 digest is the lookup key. Every row and the
schema definition are authenticated with an HMAC key derived from an explicitly injected
`SecretValue` and deployment salt. A wrong key, changed schema, or modified row fails closed.
Neither key material nor raw handles appear in model representations or error messages.

The database deliberately retains consumed, revoked, and expired decisions for audit. Operators
must set retention, backup, disk encryption, and access controls appropriate to their
environment. On POSIX, ACC requires owner-only permissions. On Windows, deployment remains
responsible for applying an ACL restricted to the approval and Gateway service identities.

## Lifetime and revocation

Approval lifetime is capped at 900 seconds and can never exceed the prepared Action lifetime.
Verification atomically changes `approved` to `consumed`; replay fails. `revoke()` requires the
opaque handle and records `revoked_by`, so knowledge of a public decision ID alone cannot revoke
a decision. Expired, consumed, and revoked handles cannot later authorize an Action.

`ApprovalGrant.decision_id` and `approver_id`, plus `decision()`, provide the correlation facts
for the operator's audit pipeline. The approval database is evidence, not the sole enterprise
audit archive: production deployments should export these facts to their immutable audit sink.

## Example composition

```python
authority = SQLiteApprovalAuthority(
    "state/approvals.db",
    authority_secret=SecretValue(os.environ["ACC_APPROVAL_AUTHORITY_SECRET"]),
    deployment_salt=bytes.fromhex(os.environ["ACC_APPROVAL_AUTHORITY_SALT_HEX"]),
)
```

Use a dedicated secret and salt; do not reuse Action Store, Session Vault, operator endpoint, or
audit identity key material. This class is intentionally not selected by the CLI: deployment
composition and the external operator workflow must be explicit.
