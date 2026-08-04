"""Configurable, domain-neutral FastAPI fake REST system."""

from __future__ import annotations

import copy
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import unquote

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import JsonValue

from acc_testkit.faults import Fault

_HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}")


class FixtureConfigurationError(ValueError):
    """A fake route or fixture is internally inconsistent."""


class SimulatedTimeoutError(TimeoutError):
    """In-process FastAPI signal for a deterministic timeout outcome."""


@dataclass(frozen=True, slots=True)
class ResponseSpec:
    """A normal HTTP response backed by inline JSON, bytes, or a named fixture."""

    status_code: int = 200
    json_body: JsonValue = None
    content: bytes | None = None
    fixture: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise FixtureConfigurationError("response status must be between 100 and 599")
        selected = int(self.content is not None) + int(self.fixture is not None)
        if selected > 1:
            raise FixtureConfigurationError("response content and fixture are mutually exclusive")


type Outcome = ResponseSpec | Fault


@dataclass(frozen=True, slots=True)
class RouteFixture:
    """A declared REST route and its repeatable sequence of outcomes."""

    operation: str
    method: str
    path: str
    path_parameters: Mapping[str, str] = field(default_factory=dict)
    query_parameters: Mapping[str, str] = field(default_factory=dict)
    outcomes: tuple[Outcome, ...] = field(default_factory=lambda: (ResponseSpec(),))

    def __post_init__(self) -> None:
        if not self.operation:
            raise FixtureConfigurationError("route operation must not be empty")
        if self.method.upper() not in _HTTP_METHODS:
            raise FixtureConfigurationError(f"unsupported fake HTTP method: {self.method}")
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise FixtureConfigurationError("route path must be an origin-relative path")
        placeholders = set(_PLACEHOLDER.findall(self.path))
        if placeholders != set(self.path_parameters):
            raise FixtureConfigurationError(
                "path parameter mappings must exactly match route placeholders"
            )
        if not self.outcomes:
            raise FixtureConfigurationError("route must declare at least one outcome")


@dataclass(frozen=True, slots=True)
class CallRecord:
    """A credential-free logical operation call observed by the fake system."""

    sequence: int
    operation: str | None
    method: str
    path: str
    arguments: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class _CompiledRoute:
    index: int
    fixture: RouteFixture
    pattern: re.Pattern[str]
    placeholders: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Dispatch:
    outcome: Outcome
    record: CallRecord


class FakeRestSystem:
    """Serve configured fixtures through FastAPI or a no-socket HTTPX transport."""

    def __init__(
        self,
        routes: Sequence[RouteFixture],
        *,
        fixtures: Mapping[str, JsonValue] | None = None,
    ) -> None:
        self.fixtures = copy.deepcopy(dict(fixtures or {}))
        self._routes = self._compile_routes(routes)
        self._positions: dict[int, int] = defaultdict(int)
        self._calls: list[CallRecord] = []
        self.app = self._create_app()

    @property
    def calls(self) -> list[CallRecord]:
        """Return a defensive snapshot in deterministic sequence order."""

        return copy.deepcopy(self._calls)

    def snapshot(self) -> tuple[dict[str, object], ...]:
        """Return the recorder-protocol immutable snapshot form."""

        return tuple(
            {
                "operation": record.operation,
                "arguments": copy.deepcopy(record.arguments),
            }
            for record in self._calls
        )

    def reset(self) -> None:
        """Clear call history and rewind every route outcome sequence."""

        self._calls.clear()
        self._positions.clear()

    async def load(self, fixtures: Mapping[str, JsonValue]) -> None:
        """Install one Eval case's fixture set through the runner loader protocol."""

        self.fixtures = copy.deepcopy(dict(fixtures))

    def transport(self) -> httpx.AsyncBaseTransport:
        """Return an HTTPX transport that can raise real timeout exceptions."""

        return httpx.MockTransport(self._handle_httpx)

    def _create_app(self) -> FastAPI:
        app = FastAPI()

        async def dispatch(request: Request) -> Response:
            raw_path = cast(bytes, request.scope.get("raw_path", request.url.path.encode("ascii")))
            query_items = list(request.query_params.multi_items())
            result = self._dispatch(request.method, _path_only(raw_path), query_items)
            if result.outcome.kind == "timeout" if isinstance(result.outcome, Fault) else False:
                raise SimulatedTimeoutError("simulated timeout")
            return self._fastapi_response(result.outcome)

        app.add_api_route("/", dispatch, methods=_HTTP_METHODS)
        app.add_api_route("/{path:path}", dispatch, methods=_HTTP_METHODS)
        return app

    async def _handle_httpx(self, request: httpx.Request) -> httpx.Response:
        raw_path = _path_only(request.url.raw_path)
        result = self._dispatch(request.method, raw_path, list(request.url.params.multi_items()))
        outcome = result.outcome
        if isinstance(outcome, Fault) and outcome.kind == "timeout":
            raise httpx.ReadTimeout("simulated timeout", request=request)
        return self._httpx_response(outcome, request)

    def _dispatch(
        self,
        method: str,
        raw_path: str,
        query_items: list[tuple[str, str]],
    ) -> _Dispatch:
        for route in self._routes:
            if route.fixture.method.upper() != method.upper():
                continue
            match = route.pattern.fullmatch(raw_path)
            if match is None:
                continue
            arguments: dict[str, JsonValue] = {}
            captured = {
                placeholder: unquote(match.group(index + 1))
                for index, placeholder in enumerate(route.placeholders)
            }
            for placeholder, input_name in route.fixture.path_parameters.items():
                arguments[input_name] = captured[placeholder]
            grouped_query: dict[str, list[str]] = defaultdict(list)
            for name, value in query_items:
                grouped_query[name].append(value)
            for query_name, input_name in route.fixture.query_parameters.items():
                values = grouped_query.get(query_name)
                if values:
                    arguments[input_name] = cast(
                        JsonValue, values[0] if len(values) == 1 else values
                    )
            record = self._record(route.fixture.operation, method, raw_path, arguments)
            position = self._positions[route.index]
            self._positions[route.index] += 1
            outcome = route.fixture.outcomes[min(position, len(route.fixture.outcomes) - 1)]
            return _Dispatch(outcome=outcome, record=record)

        record = self._record(None, method, raw_path, {})
        return _Dispatch(outcome=Fault.not_found(), record=record)

    def _record(
        self,
        operation: str | None,
        method: str,
        path: str,
        arguments: dict[str, JsonValue],
    ) -> CallRecord:
        record = CallRecord(
            sequence=len(self._calls) + 1,
            operation=operation,
            method=method.upper(),
            path=path,
            arguments=copy.deepcopy(arguments),
        )
        self._calls.append(record)
        return record

    def _httpx_response(self, outcome: Outcome, request: httpx.Request) -> httpx.Response:
        status, headers, content, json_body = self._materialize(outcome)
        if content is not None:
            return httpx.Response(status, headers=headers, content=content, request=request)
        return httpx.Response(status, headers=headers, json=json_body, request=request)

    def _fastapi_response(self, outcome: Outcome) -> Response:
        status, headers, content, json_body = self._materialize(outcome)
        if content is not None:
            return Response(content=content, status_code=status, headers=headers)
        return JSONResponse(content=json_body, status_code=status, headers=headers)

    def _materialize(self, outcome: Outcome) -> tuple[int, dict[str, str], bytes | None, JsonValue]:
        if isinstance(outcome, Fault):
            if outcome.kind == "oversize":
                assert outcome.size_bytes is not None
                return (
                    200,
                    {"content-type": "application/octet-stream"},
                    b"x" * outcome.size_bytes,
                    None,
                )
            if outcome.kind == "http_status":
                assert outcome.status_code is not None and outcome.code is not None
                return outcome.status_code, {}, None, {"error": {"code": outcome.code}}
            raise SimulatedTimeoutError("simulated timeout")
        if outcome.fixture is not None:
            if outcome.fixture not in self.fixtures:
                raise FixtureConfigurationError(f"unknown response fixture: {outcome.fixture}")
            body = copy.deepcopy(self.fixtures[outcome.fixture])
        else:
            body = copy.deepcopy(outcome.json_body)
        return outcome.status_code, dict(outcome.headers), outcome.content, body

    @staticmethod
    def _compile_routes(routes: Sequence[RouteFixture]) -> tuple[_CompiledRoute, ...]:
        compiled: list[_CompiledRoute] = []
        identities: set[tuple[str, str]] = set()
        for index, fixture in enumerate(routes):
            identity = (fixture.method.upper(), fixture.path)
            if identity in identities:
                raise FixtureConfigurationError(
                    f"duplicate fake route: {identity[0]} {identity[1]}"
                )
            identities.add(identity)
            parts: list[str] = []
            placeholders: list[str] = []
            cursor = 0
            for match in _PLACEHOLDER.finditer(fixture.path):
                parts.append(re.escape(fixture.path[cursor : match.start()]))
                parts.append("([^/]+)")
                placeholders.append(match.group(1))
                cursor = match.end()
            parts.append(re.escape(fixture.path[cursor:]))
            compiled.append(
                _CompiledRoute(
                    index=index,
                    fixture=fixture,
                    pattern=re.compile("".join(parts)),
                    placeholders=tuple(placeholders),
                )
            )
        return tuple(compiled)


def _path_only(raw_path: bytes) -> str:
    return raw_path.split(b"?", 1)[0].decode("ascii")


__all__ = [
    "CallRecord",
    "FakeRestSystem",
    "FixtureConfigurationError",
    "ResponseSpec",
    "RouteFixture",
    "SimulatedTimeoutError",
]
