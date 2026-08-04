"""Small domain-neutral fixtures demonstrating acc-testkit's public API."""

from __future__ import annotations

import copy

from pydantic import JsonValue

from acc_testkit.fake_system import FakeRestSystem, ResponseSpec, RouteFixture

EXAMPLE_FIXTURES: dict[str, JsonValue] = {
    "entity": {
        "id": "entity-1",
        "label": "Example Entity",
        "tags": ["sample"],
    },
    "entities": {
        "items": [
            {
                "id": "entity-1",
                "label": "Example Entity",
                "tags": ["sample"],
            }
        ]
    },
}

EXAMPLE_ROUTES: tuple[RouteFixture, ...] = (
    RouteFixture(
        operation="example.get_entity",
        method="GET",
        path="/entities/{entity_id}",
        path_parameters={"entity_id": "entity_id"},
        outcomes=(ResponseSpec(fixture="entity"),),
    ),
    RouteFixture(
        operation="example.list_entities",
        method="GET",
        path="/entities",
        outcomes=(ResponseSpec(fixture="entities"),),
    ),
)


def create_example_system() -> FakeRestSystem:
    """Return a fresh example system with independent calls and outcome cursors."""

    return FakeRestSystem(
        routes=copy.deepcopy(EXAMPLE_ROUTES),
        fixtures=copy.deepcopy(EXAMPLE_FIXTURES),
    )


__all__ = ["EXAMPLE_FIXTURES", "EXAMPLE_ROUTES", "create_example_system"]
