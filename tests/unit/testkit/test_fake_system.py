from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from acc_testkit.fake_system import (
    CallRecord,
    FakeRestSystem,
    ResponseSpec,
    RouteFixture,
)
from acc_testkit.faults import Fault


@pytest.mark.asyncio
async def test_fake_system_serves_fixtures_and_records_operation_arguments() -> None:
    system = FakeRestSystem(
        fixtures={"entity": {"id": "entity/one", "name": "Example"}},
        routes=[
            RouteFixture(
                operation="example.get_entity",
                method="GET",
                path="/entities/{entity_id}",
                path_parameters={"entity_id": "entity_id"},
                query_parameters={"include": "include"},
                outcomes=(ResponseSpec(fixture="entity"),),
            )
        ],
    )

    assert isinstance(system.app, FastAPI)
    async with httpx.AsyncClient(
        transport=system.transport(), base_url="https://fake.example.test"
    ) as client:
        response = await client.get(
            "/entities/entity%2Fone",
            params=[("include", "details"), ("include", "history")],
            headers={"Authorization": "Bearer test-secret"},
        )

    assert response.status_code == 200
    assert response.json() == {"id": "entity/one", "name": "Example"}
    assert system.calls == [
        CallRecord(
            sequence=1,
            operation="example.get_entity",
            method="GET",
            path="/entities/entity%2Fone",
            arguments={
                "entity_id": "entity/one",
                "include": ["details", "history"],
            },
        )
    ]
    assert "test-secret" not in repr(system.calls)


@pytest.mark.asyncio
async def test_fake_system_replays_faults_in_declared_order_and_repeats_last_outcome() -> None:
    system = FakeRestSystem(
        routes=[
            RouteFixture(
                operation="example.list_entities",
                method="GET",
                path="/entities",
                outcomes=(
                    Fault.forbidden(),
                    Fault.not_found(),
                    Fault.http_status(503, code="UPSTREAM_UNAVAILABLE"),
                    ResponseSpec(json_body={"items": []}),
                ),
            )
        ]
    )

    async with httpx.AsyncClient(transport=system.transport(), base_url="http://fake") as client:
        responses = [await client.get("/entities") for _ in range(5)]

    assert [response.status_code for response in responses] == [403, 404, 503, 200, 200]
    assert responses[0].json() == {"error": {"code": "FORBIDDEN"}}
    assert responses[1].json() == {"error": {"code": "NOT_FOUND"}}
    assert responses[2].json() == {"error": {"code": "UPSTREAM_UNAVAILABLE"}}
    assert [call.sequence for call in system.calls] == [1, 2, 3, 4, 5]


@pytest.mark.asyncio
async def test_fake_system_simulates_timeout_and_oversize_without_sleeping() -> None:
    system = FakeRestSystem(
        routes=[
            RouteFixture(
                operation="example.get_entity",
                method="GET",
                path="/timeout",
                outcomes=(Fault.timeout(),),
            ),
            RouteFixture(
                operation="example.export_entities",
                method="GET",
                path="/oversize",
                outcomes=(Fault.oversize(257),),
            ),
        ]
    )

    async with httpx.AsyncClient(transport=system.transport(), base_url="http://fake") as client:
        with pytest.raises(httpx.ReadTimeout, match="simulated timeout"):
            await client.get("/timeout")
        response = await client.get("/oversize")

    assert response.status_code == 200
    assert len(response.content) == 257
    assert [call.operation for call in system.calls] == [
        "example.get_entity",
        "example.export_entities",
    ]


@pytest.mark.asyncio
async def test_fake_system_records_unmatched_requests_and_reset_is_deterministic() -> None:
    system = FakeRestSystem(routes=[])

    async with httpx.AsyncClient(transport=system.transport(), base_url="http://fake") as client:
        response = await client.get("/missing")

    assert response.status_code == 404
    assert system.calls[0].operation is None
    system.reset()
    assert system.calls == []


@pytest.mark.asyncio
async def test_fake_system_loads_eval_fixtures_and_serves_them_through_fastapi() -> None:
    system = FakeRestSystem(
        fixtures={"entity": {"id": "old"}},
        routes=[
            RouteFixture(
                operation="example.get_entity",
                method="GET",
                path="/entity",
                outcomes=(ResponseSpec(fixture="entity"),),
            )
        ],
    )
    await system.load({"entity": {"id": "loaded-for-eval"}})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=system.app), base_url="http://fake"
    ) as client:
        response = await client.get("/entity")

    assert response.status_code == 200
    assert response.json() == {"id": "loaded-for-eval"}
    assert system.snapshot() == ({"operation": "example.get_entity", "arguments": {}},)


@pytest.mark.asyncio
async def test_fake_system_supports_hyphenated_declared_placeholders() -> None:
    system = FakeRestSystem(
        routes=[
            RouteFixture(
                operation="example.get_entity",
                method="GET",
                path="/entities/{entity-id}",
                path_parameters={"entity-id": "entity_id"},
                outcomes=(ResponseSpec(json_body={"ok": True}),),
            )
        ]
    )

    async with httpx.AsyncClient(transport=system.transport(), base_url="http://fake") as client:
        response = await client.get("/entities/e-1")

    assert response.status_code == 200
    assert system.snapshot()[0]["arguments"] == {"entity_id": "e-1"}
