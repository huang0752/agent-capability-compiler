"""Assertions for proving an adapter server matches its read-only contract."""

from __future__ import annotations

from fastapi.routing import APIRoute

from acc_adapter_sdk.contracts import join_adapter_path
from acc_adapter_sdk.server import AdapterServer

_READ_ONLY_METHODS = {"GET", "HEAD"}


class AdapterContractAssertionError(AssertionError):
    """A server's actual routes do not match its declared adapter contract."""


def _format_routes(routes: set[tuple[str, str]]) -> str:
    return ", ".join(f"{method} {path}" for path, method in sorted(routes))


def assert_adapter_contract(server: AdapterServer) -> None:
    """Assert exact operation registration and the absence of write routes."""

    declared_ids = {operation.id for operation in server.contract.operations}
    registered_ids = set(server.registered_operation_ids)
    missing_ids = sorted(declared_ids - registered_ids)
    if missing_ids:
        raise AdapterContractAssertionError(
            f"missing registered operations: {', '.join(missing_ids)}"
        )
    extra_ids = sorted(registered_ids - declared_ids)
    if extra_ids:
        raise AdapterContractAssertionError(
            f"undeclared registered operations: {', '.join(extra_ids)}"
        )

    expected_routes = {(server.contract.health.path, "GET")}
    expected_routes.update(
        (
            join_adapter_path(server.contract.base_path, operation.path),
            operation.method,
        )
        for operation in server.contract.operations
    )
    actual_routes = {
        (route.path, method)
        for route in server.app.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    unsafe_routes = {route for route in actual_routes if route[1] not in _READ_ONLY_METHODS}
    if unsafe_routes:
        raise AdapterContractAssertionError(
            f"unsafe adapter route methods: {_format_routes(unsafe_routes)}"
        )
    undeclared_routes = actual_routes - expected_routes
    if undeclared_routes:
        raise AdapterContractAssertionError(
            f"undeclared adapter routes: {_format_routes(undeclared_routes)}"
        )
    missing_routes = expected_routes - actual_routes
    if missing_routes:
        raise AdapterContractAssertionError(
            f"missing adapter routes: {_format_routes(missing_routes)}"
        )


__all__ = ["AdapterContractAssertionError", "assert_adapter_contract"]
