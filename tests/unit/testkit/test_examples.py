from __future__ import annotations

import httpx
import pytest

from acc_testkit.examples import EXAMPLE_FIXTURES, EXAMPLE_ROUTES, create_example_system


@pytest.mark.asyncio
async def test_domain_neutral_example_data_runs_without_external_services() -> None:
    assert EXAMPLE_FIXTURES["entity"] == {
        "id": "entity-1",
        "label": "Example Entity",
        "tags": ["sample"],
    }
    assert [route.operation for route in EXAMPLE_ROUTES] == [
        "example.get_entity",
        "example.list_entities",
    ]
    system = create_example_system()

    async with httpx.AsyncClient(transport=system.transport(), base_url="http://example") as client:
        response = await client.get("/entities/entity-1")

    assert response.json() == EXAMPLE_FIXTURES["entity"]
    assert system.snapshot()[0]["arguments"] == {"entity_id": "entity-1"}
    assert create_example_system().snapshot() == ()
