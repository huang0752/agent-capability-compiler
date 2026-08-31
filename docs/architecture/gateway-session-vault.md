# Encrypted Gateway Session Vault

`SQLiteGatewaySessionVault` is the platform-neutral, single-node persistence option for
Streamable HTTP Gateway sessions. It is opt-in through `GatewaySessionVaultConfig`; no path,
key, salt, or secret reference is exposed through runtime metadata.

## Security boundary

- The Gateway token is never stored. Only its SHA-256 digest is indexed.
- Session IDs are indexed only as HMAC-SHA-256 digests derived from a separate HKDF key.
- The complete session record and recoverable `AuthenticationResult` share one AES-256-GCM
  ciphertext and one SQLite transaction. Login identity and password are never included.
- Every write uses a random 96-bit nonce. AEAD associated data binds schema version, project,
  verified Pack digest, scope-mapping and deployment-scope-ceiling digests, session digest, and
  token digest.
- A KEK of at least 32 bytes and deployment salt of at least 16 bytes must be injected as
  `SecretValue`/bytes. Neither is written to SQLite. A key-check ciphertext makes a wrong key,
  changed deployment binding, or tampered metadata fail before startup completes.
- Unknown schemas, altered rows, unsafe link/reparse paths, and invalid restored semantic
  bindings fail closed. POSIX files are owner-only; Windows deployments remain responsible for
  applying an appropriate operator-only ACL.

The Vault uses wall-clock timestamps (`time.time`) consistently across the Gateway session
store, authentication strategy, and session service. Monotonic timestamps are intentionally not
persisted across processes.

## Lifecycle

During ASGI lifespan startup, every row is authenticated and decoded before active source
authentication state is rebound. The Gateway does not become ready if any row, key, version, or
binding is invalid. Sessions already marked `reauth_required` are restored as terminal
reauthentication requirements and are not silently logged in.

Normal process shutdown checkpoints encrypted rows for restart while clearing in-process state.
Fatal service shutdown and explicit logout durably delete rows before clearing memory. A source
401 durably records `reauth_required` before its source authentication state is invalidated.

This is a single-process/single-node facility, not a distributed session database. Local
development Operator approval observations and grants remain intentionally in memory; after a
restart an old Action approval request returns not found and must be prepared again.

AES-GCM authenticates the current database contents and deployment bindings, but it does not
detect an attacker replaying a complete older, previously valid database snapshot together with
its WAL. Deployments whose threat model includes full-file rollback need an external protected
monotonic epoch (for example an OS key store or TPM-backed anchor). This reference implementation
does not claim rollback resistance. Windows file ACL confidentiality also remains an operator
deployment responsibility; rejecting reparse points is not an ACL substitute.

## Composition example

```python
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import GatewaySessionVaultConfig, create_gateway_runtime

composition = create_gateway_runtime(
    # existing pack_path, settings, environment, and scope arguments omitted
    session_vault=GatewaySessionVaultConfig(
        db_path="runtime-data/gateway-sessions.db",
        kek=SecretValue(session_vault_key),
        deployment_salt=deployment_salt,
    ),
)
```

The parent directory must already exist and must not traverse links or Windows reparse points.
