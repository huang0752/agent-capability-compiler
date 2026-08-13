"""Bounded process-local resource locks for local development Action sandboxes."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from acc_runtime.errors import RuntimeError as AccRuntimeError


class ActionResourceLockCapacityError(AccRuntimeError):
    """The bounded local lock table cannot safely admit another resource."""

    code = "ACC_RUNTIME_ACTION_RESOURCE_LOCK_CAPACITY"
    status = 503


@runtime_checkable
class ActionResourceLock(Protocol):
    """Operator-owned lock seam for cooperating ACC runtime calls only."""

    development_only: bool

    def hold(self, key: str) -> AbstractAsyncContextManager[None]: ...


@dataclass(slots=True)
class _Entry:
    lock: asyncio.Lock
    users: int = 0


class InMemoryActionResourceLock:
    """Bounded process-local lock table; never a source atomicity guarantee."""

    development_only = True

    def __init__(self, *, max_entries: int = 1024) -> None:
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self._max_entries = max_entries
        self._entries: dict[str, _Entry] = {}
        self._table_lock = asyncio.Lock()

    @asynccontextmanager
    async def hold(self, key: str) -> AsyncIterator[None]:
        if not isinstance(key, str) or not key:
            raise ValueError("resource lock key must be a nonempty string")
        async with self._table_lock:
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= self._max_entries:
                    raise ActionResourceLockCapacityError(
                        "Local development Action resource lock capacity is exhausted"
                    )
                entry = _Entry(lock=asyncio.Lock())
                self._entries[key] = entry
            entry.users += 1
        acquired = False
        try:
            await entry.lock.acquire()
            acquired = True
            yield
        finally:
            if acquired:
                entry.lock.release()
            async with self._table_lock:
                entry.users -= 1
                if entry.users == 0:
                    self._entries.pop(key, None)


__all__ = [
    "ActionResourceLock",
    "ActionResourceLockCapacityError",
    "InMemoryActionResourceLock",
]
