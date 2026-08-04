"""Logical operation recording for runtime Eval and E2E tests."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import JsonValue


class OperationProvider(Protocol):
    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue: ...


class RecordedOperationCall(Protocol):
    operation: str | None
    arguments: Mapping[str, JsonValue]


@runtime_checkable
class CallRecorder(Protocol):
    """Shared recorder surface consumed by Eval assertion runners."""

    def snapshot(self) -> Sequence[Mapping[str, object]]: ...

    def reset(self) -> None: ...


class RecordingConfigurationError(ValueError):
    """A wrapped compiled operation has no usable logical id."""


@dataclass(frozen=True, slots=True)
class OperationCallRecord:
    sequence: int
    operation: str
    arguments: dict[str, JsonValue]


class RecordingOperationProvider:
    """Transparent operation-provider wrapper with defensive call snapshots."""

    def __init__(self, delegate: OperationProvider) -> None:
        self.delegate = delegate
        self._calls: list[OperationCallRecord] = []

    @property
    def calls(self) -> list[OperationCallRecord]:
        return copy.deepcopy(self._calls)

    def snapshot(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "operation": record.operation,
                "arguments": copy.deepcopy(record.arguments),
            }
            for record in self._calls
        )

    def reset(self) -> None:
        self._calls.clear()

    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        operation_id = operation.get("id")
        if not isinstance(operation_id, str) or not operation_id:
            raise RecordingConfigurationError("recorded operation requires a non-empty string id")
        self._calls.append(
            OperationCallRecord(
                sequence=len(self._calls) + 1,
                operation=operation_id,
                arguments=copy.deepcopy(dict(arguments)),
            )
        )
        return await self.delegate.call(operation, arguments)


__all__ = [
    "CallRecorder",
    "OperationCallRecord",
    "OperationProvider",
    "RecordedOperationCall",
    "RecordingConfigurationError",
    "RecordingOperationProvider",
]
