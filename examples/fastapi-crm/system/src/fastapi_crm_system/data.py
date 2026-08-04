"""Pure synthetic, immutable CRM example data."""

from __future__ import annotations

from datetime import date

from fastapi_crm_system.models import Contact, Customer, Followup, Todo

CUSTOMERS = (
    Customer(
        id="cust-a-001",
        tenant_id="tenant-a",
        name="Acme Manufacturing",
        industry="manufacturing",
        owner="Ada",
    ),
    Customer(
        id="cust-a-002",
        tenant_id="tenant-a",
        name="Beacon Retail",
        industry="retail",
        owner="Ben",
    ),
    Customer(
        id="cust-b-001",
        tenant_id="tenant-b",
        name="Cedar Logistics",
        industry="logistics",
        owner="Chen",
    ),
)

CONTACTS = (
    Contact(
        id="contact-a-001",
        tenant_id="tenant-a",
        customer_id="cust-a-001",
        name="Avery Stone",
        email="avery@example.test",
        role="operations",
    ),
    Contact(
        id="contact-b-001",
        tenant_id="tenant-b",
        customer_id="cust-b-001",
        name="Casey Reed",
        email="casey@example.test",
        role="procurement",
    ),
)

FOLLOWUPS = (
    Followup(
        id="followup-a-001",
        tenant_id="tenant-a",
        customer_id="cust-a-001",
        summary="Confirm read-only API inventory",
        due_date=date(2026, 1, 10),
        status="open",
    ),
    Followup(
        id="followup-a-002",
        tenant_id="tenant-a",
        customer_id="cust-a-001",
        summary="Review synthetic account notes",
        due_date=date(2026, 1, 12),
        status="completed",
    ),
    Followup(
        id="followup-b-001",
        tenant_id="tenant-b",
        customer_id="cust-b-001",
        summary="Confirm logistics demo scope",
        due_date=date(2026, 1, 20),
        status="open",
    ),
)

TODOS = (
    Todo(
        id="todo-a-001",
        tenant_id="tenant-a",
        customer_id="cust-a-001",
        title="Prepare synthetic customer summary",
        due_date=date(2026, 1, 14),
        completed=False,
    ),
    Todo(
        id="todo-a-002",
        tenant_id="tenant-a",
        customer_id="cust-a-001",
        title="Archive completed demo checklist",
        due_date=date(2026, 1, 9),
        completed=True,
    ),
)

__all__ = ["CONTACTS", "CUSTOMERS", "FOLLOWUPS", "TODOS"]
