from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from fastapi_crm_system import app

TENANT_A_READER = "demo-tenant-a-reader"
TENANT_A_CUSTOMER_READER = "demo-tenant-a-customer-reader"
TENANT_B_READER = "demo-tenant-b-reader"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://crm.example.test",
    ) as test_client:
        yield test_client


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("authorization", [None, "Bearer invalid-demo-token"])
async def test_missing_or_invalid_bearer_token_is_unauthorized(
    client: AsyncClient,
    authorization: str | None,
) -> None:
    headers = {"Authorization": authorization} if authorization is not None else {}

    response = await client.get("/customers", params={"tenant_id": "tenant-a"}, headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "CRM_AUTH_INVALID"
    assert response.headers["www-authenticate"] == "Bearer"


async def test_route_scope_is_enforced(client: AsyncClient) -> None:
    response = await client.get(
        "/customers/cust-a-001/contacts",
        params={"tenant_id": "tenant-a"},
        headers=_headers(TENANT_A_CUSTOMER_READER),
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "CRM_SCOPE_DENIED"


async def test_request_tenant_must_match_token_tenant(client: AsyncClient) -> None:
    response = await client.get(
        "/customers",
        params={"tenant_id": "tenant-b"},
        headers=_headers(TENANT_A_READER),
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "CRM_TENANT_MISMATCH"


async def test_cross_tenant_record_is_hidden_as_not_found(client: AsyncClient) -> None:
    response = await client.get(
        "/customers/cust-b-001",
        params={"tenant_id": "tenant-a"},
        headers=_headers(TENANT_A_READER),
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "CRM_CUSTOMER_NOT_FOUND"


async def test_search_and_customer_context_routes_return_synthetic_tenant_data(
    client: AsyncClient,
) -> None:
    headers = _headers(TENANT_A_READER)
    tenant = {"tenant_id": "tenant-a"}

    search = await client.get("/customers", params={**tenant, "q": "acme"}, headers=headers)
    customer = await client.get("/customers/cust-a-001", params=tenant, headers=headers)
    contacts = await client.get("/customers/cust-a-001/contacts", params=tenant, headers=headers)
    followups = await client.get("/customers/cust-a-001/followups", params=tenant, headers=headers)
    todos = await client.get("/customers/cust-a-001/todos", params=tenant, headers=headers)

    assert search.status_code == 200
    assert [item["id"] for item in search.json()] == ["cust-a-001"]
    assert customer.json() == {
        "id": "cust-a-001",
        "tenant_id": "tenant-a",
        "name": "Acme Manufacturing",
        "industry": "manufacturing",
        "owner": "Ada",
    }
    assert [item["id"] for item in contacts.json()] == ["contact-a-001"]
    assert [item["id"] for item in followups.json()] == [
        "followup-a-001",
        "followup-a-002",
    ]
    assert [item["id"] for item in todos.json()] == ["todo-a-001", "todo-a-002"]


async def test_overdue_followups_use_explicit_as_of_date(client: AsyncClient) -> None:
    response = await client.get(
        "/followups/overdue",
        params={"tenant_id": "tenant-a", "as_of": "2026-01-15"},
        headers=_headers(TENANT_A_READER),
    )

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == ["followup-a-001"]


async def test_unknown_customer_is_not_found(client: AsyncClient) -> None:
    response = await client.get(
        "/customers/missing",
        params={"tenant_id": "tenant-a"},
        headers=_headers(TENANT_A_READER),
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "CRM_CUSTOMER_NOT_FOUND"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "path",
    [
        "/customers",
        "/customers/cust-a-001",
        "/customers/cust-a-001/contacts",
        "/customers/cust-a-001/followups",
        "/customers/cust-a-001/todos",
        "/followups/overdue",
    ],
)
async def test_all_business_routes_reject_write_methods(
    client: AsyncClient,
    method: str,
    path: str,
) -> None:
    response = await client.request(
        method,
        path,
        params={"tenant_id": "tenant-a", "as_of": "2026-01-15"},
        headers=_headers(TENANT_A_READER),
    )

    assert response.status_code == 405


async def test_openapi_declares_bearer_security_and_get_only_business_paths(
    client: AsyncClient,
) -> None:
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()
    assert document["components"]["securitySchemes"]["DemoBearer"] == {
        "type": "http",
        "scheme": "bearer",
    }
    expected_paths = {
        "/customers",
        "/customers/{customer_id}",
        "/customers/{customer_id}/contacts",
        "/customers/{customer_id}/followups",
        "/customers/{customer_id}/todos",
        "/followups/overdue",
    }
    assert set(document["paths"]) == expected_paths
    assert all(set(path_item) == {"get"} for path_item in document["paths"].values())


async def test_tenant_b_token_only_sees_tenant_b_data(client: AsyncClient) -> None:
    response = await client.get(
        "/customers",
        params={"tenant_id": "tenant-b"},
        headers=_headers(TENANT_B_READER),
    )

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == ["cust-b-001"]
