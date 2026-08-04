"""Read-only FastAPI CRM used as an independent ACC source-system fixture."""

from __future__ import annotations

from datetime import date
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query

from fastapi_crm_system.auth import (
    CONTACT_READ,
    CUSTOMER_READ,
    FOLLOWUP_READ,
    TODO_READ,
    AccessContext,
    require_scope,
)
from fastapi_crm_system.data import CONTACTS, CUSTOMERS, FOLLOWUPS, TODOS
from fastapi_crm_system.models import Contact, Customer, Followup, Todo

app = FastAPI(
    title="Synthetic FastAPI CRM",
    description="Independent, read-only source system used by the ACC example.",
    version="0.1.0",
)

CustomerAccess = Annotated[AccessContext, Depends(require_scope(CUSTOMER_READ))]
ContactAccess = Annotated[AccessContext, Depends(require_scope(CONTACT_READ))]
FollowupAccess = Annotated[AccessContext, Depends(require_scope(FOLLOWUP_READ))]
TodoAccess = Annotated[AccessContext, Depends(require_scope(TODO_READ))]


def _customer(customer_id: str, tenant_id: str) -> Customer:
    customer = next(
        (
            item
            for item in CUSTOMERS
            if item.id == customer_id and item.tenant_id == tenant_id
        ),
        None,
    )
    if customer is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CRM_CUSTOMER_NOT_FOUND", "message": "Customer was not found."},
        )
    return customer


@app.get("/customers", response_model=list[Customer], operation_id="search_customers")
async def search_customers(
    access: CustomerAccess,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> list[Customer]:
    """Search customers in the authenticated tenant."""

    query = q.casefold() if q is not None else None
    return [
        item
        for item in CUSTOMERS
        if item.tenant_id == access.tenant_id
        and (
            query is None
            or query in item.name.casefold()
            or query in item.industry.casefold()
            or query in item.owner.casefold()
        )
    ]


@app.get(
    "/customers/{customer_id}",
    response_model=Customer,
    operation_id="get_customer",
)
async def get_customer(customer_id: str, access: CustomerAccess) -> Customer:
    """Return one customer without revealing cross-tenant existence."""

    return _customer(customer_id, access.tenant_id)


@app.get(
    "/customers/{customer_id}/contacts",
    response_model=list[Contact],
    operation_id="list_customer_contacts",
)
async def list_customer_contacts(customer_id: str, access: ContactAccess) -> list[Contact]:
    """List contacts after authorizing and resolving the parent customer."""

    _customer(customer_id, access.tenant_id)
    return [
        item
        for item in CONTACTS
        if item.tenant_id == access.tenant_id and item.customer_id == customer_id
    ]


@app.get(
    "/customers/{customer_id}/followups",
    response_model=list[Followup],
    operation_id="list_customer_followups",
)
async def list_customer_followups(customer_id: str, access: FollowupAccess) -> list[Followup]:
    """List followups after authorizing and resolving the parent customer."""

    _customer(customer_id, access.tenant_id)
    return [
        item
        for item in FOLLOWUPS
        if item.tenant_id == access.tenant_id and item.customer_id == customer_id
    ]


@app.get(
    "/customers/{customer_id}/todos",
    response_model=list[Todo],
    operation_id="list_customer_todos",
)
async def list_customer_todos(customer_id: str, access: TodoAccess) -> list[Todo]:
    """List todos after authorizing and resolving the parent customer."""

    _customer(customer_id, access.tenant_id)
    return [
        item
        for item in TODOS
        if item.tenant_id == access.tenant_id and item.customer_id == customer_id
    ]


@app.get(
    "/followups/overdue",
    response_model=list[Followup],
    operation_id="find_overdue_followups",
)
async def find_overdue_followups(
    access: FollowupAccess,
    as_of: Annotated[date, Query(description="Fixed evaluation date; no server clock is used.")],
) -> list[Followup]:
    """Return open followups due before the caller-supplied deterministic date."""

    return [
        item
        for item in FOLLOWUPS
        if item.tenant_id == access.tenant_id
        and item.status == "open"
        and item.due_date < as_of
    ]


__all__ = ["app"]
