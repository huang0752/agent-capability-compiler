# SQLite Action Store

`SQLiteActionStore` is ACC Runtime's durable, restart-safe implementation of the
`ActionStore` protocol. A trusted host constructs it and injects it into the
runtime; it is not selected implicitly by the CLI.

```python
from acc_runtime.actions import SQLiteActionStore

store = SQLiteActionStore(
    "C:/ProgramData/acc/actions.db",
    operator_secret=operator_secret_bytes,
    deployment_salt=deployment_salt_bytes,
)
```

Both operator values are mandatory, must come from an operator-controlled
secret source, and are never stored in SQLite. Reusing the same database after
a restart requires the same values. Rotating either value intentionally makes
the existing database fail authentication; migration or archival must therefore
be an explicit operator procedure.

## Persistence and integrity

- The raw Action handle is never stored. The database key is its SHA-256 digest.
- Principal and session identifiers are stored only as keyed, deployment-scoped
  digests. Pack, input, and preview digests remain part of every sealed binding.
- JSON payloads are stored as canonical UTF-8 bytes. They are not encrypted;
  filesystem confidentiality remains an operator responsibility.
- Every row is authenticated with an operator-secret-derived HMAC. The actual
  `sqlite_master` definitions, schema version, application id, and metadata are
  also authenticated. Unexpected schema objects, altered rows, a wrong secret,
  or unsupported versions fail closed.
- Transitions use `BEGIN IMMEDIATE` and a status-qualified SQL update. SQLite
  serializes writers across processes; a lock that outlives the configured busy
  timeout is reported as an Action state conflict.
- WAL and `synchronous=FULL` are enabled. `close()` validates a bounded number of
  payload-free records and closes the store logically; it does not erase the
  database, so a new instance can recover the state.

`max_actions` is a hard retained-record bound. Expired and terminal records are
not silently discarded. Operators must use an explicit, separately designed
retention process rather than treating `close()` as cleanup.

## Filesystem boundary

The database parent must already exist. ACC rejects symlinks and Windows
reparse points (including directory junctions) anywhere in the parent chain,
and requires the database and SQLite sidecars to be regular non-link files. On
POSIX, an existing database with group or other permission bits is rejected and
new files are set to owner-only mode.

On Windows, these checks do **not** prove that the enclosing directory or file
ACL grants access only to the service identity. The operator must provision and
audit a dedicated ACL-protected directory. ACC deliberately makes no stronger
Windows ACL guarantee than it can verify locally.
