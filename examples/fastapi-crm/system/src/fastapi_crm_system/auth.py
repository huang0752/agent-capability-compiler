"""Explicit demo-only Bearer authentication and tenant authorization."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

DEMO_TENANT_A_READER_TOKEN = "demo-tenant-a-reader"
DEMO_TENANT_A_CUSTOMER_READER_TOKEN = "demo-tenant-a-customer-reader"
DEMO_TENANT_B_READER_TOKEN = "demo-tenant-b-reader"

CUSTOMER_READ = "customer.read"
CONTACT_READ = "contact.read"
FOLLOWUP_READ = "followup.read"
TODO_READ = "todo.read"

_ALL_READ_SCOPES = frozenset({CUSTOMER_READ, CONTACT_READ, FOLLOWUP_READ, TODO_READ})
_BEARER = HTTPBearer(auto_error=False, scheme_name="DemoBearer")


@dataclass(frozen=True, slots=True)
class Principal:
    """Identity derived only from a synthetic demo token."""

    tenant_id: str
    scopes: frozenset[str]


@dataclass(frozen=True, slots=True)
class AccessContext:
    """Authorized request tenant bound to the token tenant."""

    tenant_id: str


_DEMO_PRINCIPALS = {
    DEMO_TENANT_A_READER_TOKEN: Principal("tenant-a", _ALL_READ_SCOPES),
    DEMO_TENANT_A_CUSTOMER_READER_TOKEN: Principal(
        "tenant-a",
        frozenset({CUSTOMER_READ}),
    ),
    DEMO_TENANT_B_READER_TOKEN: Principal("tenant-b", _ALL_READ_SCOPES),
}


def _error(status_code: int, code: str, message: str) -> HTTPException:
    headers = (
        {"WWW-Authenticate": "Bearer"}
        if status_code == status.HTTP_401_UNAUTHORIZED
        else None
    )
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
        headers=headers,
    )


async def authenticated_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_BEARER)],
) -> Principal:
    """Resolve a fixed demo principal without accepting external credentials."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _error(401, "CRM_AUTH_INVALID", "A valid demo Bearer token is required.")
    principal = _DEMO_PRINCIPALS.get(credentials.credentials)
    if principal is None:
        raise _error(401, "CRM_AUTH_INVALID", "A valid demo Bearer token is required.")
    return principal


type AccessDependency = Callable[..., Coroutine[Any, Any, AccessContext]]


def require_scope(required_scope: str) -> AccessDependency:
    """Build a dependency enforcing scope and token/request tenant equality."""

    async def authorized_access(
        tenant_id: Annotated[str, Query(min_length=1)],
        principal: Annotated[Principal, Depends(authenticated_principal)],
    ) -> AccessContext:
        if tenant_id != principal.tenant_id:
            raise _error(403, "CRM_TENANT_MISMATCH", "Request tenant does not match token tenant.")
        if required_scope not in principal.scopes:
            raise _error(403, "CRM_SCOPE_DENIED", "Token does not grant the required scope.")
        return AccessContext(tenant_id=tenant_id)

    return authorized_access


__all__ = [
    "CONTACT_READ",
    "CUSTOMER_READ",
    "DEMO_TENANT_A_CUSTOMER_READER_TOKEN",
    "DEMO_TENANT_A_READER_TOKEN",
    "DEMO_TENANT_B_READER_TOKEN",
    "FOLLOWUP_READ",
    "TODO_READ",
    "AccessContext",
    "Principal",
    "authenticated_principal",
    "require_scope",
]
