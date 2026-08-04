"""FastAPI server primitives for fixed, read-only adapter contracts."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI
from pydantic import ValidationError

from acc_adapter_sdk.contracts import AdapterContract, join_adapter_path

_READ_ONLY_METHODS = {"GET", "HEAD"}


class AdapterRegistrationError(ValueError):
    """An adapter route cannot be safely registered from its fixed contract."""


class AdapterServer:
    """A small FastAPI wrapper that registers only declared GET/HEAD routes."""

    def __init__(self, contract: AdapterContract) -> None:
        for operation in contract.operations:
            if operation.method not in _READ_ONLY_METHODS:
                raise AdapterRegistrationError(
                    f"adapter operation must be read-only: {operation.id}"
                )
        try:
            validated_contract = AdapterContract.model_validate(contract.model_dump(mode="python"))
        except ValidationError as exc:
            raise AdapterRegistrationError("adapter contract is invalid") from exc

        self.contract = validated_contract
        self.app = FastAPI(
            title=validated_contract.id,
            version=validated_contract.version,
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )
        self._operation_index = {
            operation.id: operation for operation in validated_contract.operations
        }
        self._registered: set[str] = set()
        self._health_adapter = {
            "id": validated_contract.id,
            "version": validated_contract.version,
        }
        self._health_metadata = dict(validated_contract.health.metadata)
        self.app.add_api_route(
            validated_contract.health.path,
            self._health,
            methods=["GET"],
            include_in_schema=False,
            name="adapter-health",
        )

    @classmethod
    def from_contract_file(
        cls,
        path: str | os.PathLike[str],
    ) -> AdapterServer:
        """Load a strict adapter contract from one UTF-8 YAML file."""

        contract_path = Path(path)
        try:
            document = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise AdapterRegistrationError("cannot read adapter contract YAML") from exc
        if not isinstance(document, dict):
            raise AdapterRegistrationError("adapter contract YAML must contain an object")
        try:
            contract = AdapterContract.model_validate(document)
        except ValidationError as exc:
            raise AdapterRegistrationError("adapter contract YAML is invalid") from exc
        return cls(contract)

    @property
    def registered_operation_ids(self) -> tuple[str, ...]:
        """Return registered operation ids in deterministic order."""

        return tuple(sorted(self._registered))

    def register_operation(
        self,
        operation_id: str,
        handler: Callable[..., Any],
    ) -> None:
        """Bind a handler to one operation already declared by the contract."""

        operation = self._operation_index.get(operation_id)
        if operation is None:
            raise AdapterRegistrationError(f"adapter operation is not declared: {operation_id}")
        if operation_id in self._registered:
            raise AdapterRegistrationError(
                f"adapter operation is already registered: {operation_id}"
            )
        if operation.method not in _READ_ONLY_METHODS:
            raise AdapterRegistrationError(f"adapter operation must be read-only: {operation_id}")
        if not callable(handler):
            raise AdapterRegistrationError("adapter operation handler must be callable")

        self.app.add_api_route(
            join_adapter_path(self.contract.base_path, operation.path),
            handler,
            methods=[operation.method],
            summary=operation.summary,
            operation_id=operation.id,
            name=operation.id,
        )
        self._registered.add(operation_id)

    async def _health(self) -> dict[str, object]:
        return {
            "status": "ok",
            "schema_version": self.contract.schema_version,
            "adapter": dict(self._health_adapter),
            "metadata": dict(self._health_metadata),
        }


__all__ = ["AdapterRegistrationError", "AdapterServer"]
