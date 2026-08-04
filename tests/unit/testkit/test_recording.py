from __future__ import annotations

from collections.abc import Mapping

import pytest
from pydantic import JsonValue

from acc_testkit.fake_system import FakeRestSystem, ResponseSpec, RouteFixture
from acc_testkit.recording import (
    CallRecorder,
    RecordingOperationProvider,
)


class DelegateProvider:
    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        if operation["id"] == "example.fail":
            raise LookupError("synthetic failure")
        return {"received": dict(arguments)}


@pytest.mark.asyncio
async def test_recording_provider_wraps_delegate_and_returns_defensive_snapshots() -> None:
    provider = RecordingOperationProvider(DelegateProvider())
    arguments: dict[str, JsonValue] = {"entity": {"id": "e-1"}}

    result = await provider.call({"id": "example.get_entity"}, arguments)
    arguments["entity"] = {"id": "mutated"}

    assert result == {"received": {"entity": {"id": "e-1"}}}
    assert provider.snapshot() == (
        {
            "operation": "example.get_entity",
            "arguments": {"entity": {"id": "e-1"}},
        },
    )
    exposed = provider.calls
    exposed[0].arguments["entity"] = {"id": "also-mutated"}
    assert provider.snapshot()[0]["arguments"] == {"entity": {"id": "e-1"}}


@pytest.mark.asyncio
async def test_recording_provider_keeps_failed_calls_and_reset_rewinds_sequence() -> None:
    provider = RecordingOperationProvider(DelegateProvider())

    with pytest.raises(LookupError, match="synthetic failure"):
        await provider.call({"id": "example.fail"}, {"id": "e-1"})

    assert provider.snapshot()[0]["operation"] == "example.fail"
    provider.reset()
    assert provider.snapshot() == ()
    await provider.call({"id": "example.get_entity"}, {})
    assert provider.calls[0].sequence == 1


def test_fake_rest_system_implements_the_same_recorder_protocol() -> None:
    system = FakeRestSystem(
        routes=[
            RouteFixture(
                operation="example.list_entities",
                method="GET",
                path="/entities",
                outcomes=(ResponseSpec(json_body=[]),),
            )
        ]
    )

    assert isinstance(system, CallRecorder)
    assert system.snapshot() == ()
