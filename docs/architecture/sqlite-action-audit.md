# Durable SQLite Action audit

`SQLiteActionAuditSink` is ACC's platform-neutral, single-node reference
implementation of the production `ActionAuditSink` boundary. It is opt-in and
is not wired to the CLI automatically.

## Durability and integrity

Every `emit()` opens `BEGIN IMMEDIATE`, verifies the authenticated schema and
the complete preceding chain, appends one event, and returns only after a
`synchronous=FULL` commit. WAL mode plus the SQLite writer lock serializes
concurrent processes. Restart reopens and verifies the chain before accepting
new events.

Each row contains a stable 256-bit `event_id`, UTC epoch timestamp, minimized
Action event, previous MAC, and event MAC. The HMAC covers the sequence, event
ID, canonical event digest, and previous MAC. Authenticated schema metadata and
`UPDATE`/`DELETE` rejection triggers make accidental mutation fail closed;
startup and every append reject missing or altered schema objects, wrong keys,
gaps, reordered rows, or changed content.

The journal records only capability/status/result category, Pack digest,
deployment-salted principal/session digests, Action-handle digest, and—after a
successful approval—the Approval Authority's decision digest. It never accepts
or persists the raw Action/approval handle, credentials, Action input, preview,
provider output, concurrency token, or idempotency key. A prepare event that
occurs before creation, including a rejected prepare, has no Action digest
because no Action exists yet; a successful prepare and every later lifecycle
event require one.

## Operator responsibilities and limits

- Supply a distinct high-entropy secret of at least 32 bytes and a deployment
  salt of at least 16 bytes through a secret manager; neither is stored.
- Put the database in a pre-created, dedicated directory. ACC rejects links,
  reparse points, non-regular files, and unsafe POSIX permission bits. On
  Windows, the operator must apply and audit a restrictive NTFS ACL.
- Back up the database and key separately. Losing the key makes verification
  impossible; losing or rolling back the whole database cannot be detected by
  this database alone. Use an external immutable checkpoint, transparency log,
  or hardware/OS monotonic counter when whole-file rollback resistance is
  required.
- The reference implementation scans the bounded chain before each append. It
  favors straightforward fail-closed verification over very large-journal
  throughput. Archive verified journals under an operator-controlled retention
  policy before reaching `max_events`.

The sink provides tamper evidence, not confidentiality and not an external
approval authority. The Action Coordinator still awaits each audit append;
with `action_audit_mode=required`, a failed start event blocks mutation and a
failed completion event prevents ACC from reporting success.
