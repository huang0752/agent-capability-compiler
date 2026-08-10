"""Secret-safe client for Gateway session and runtime-attestation endpoints."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import GatewayRuntimeInfo
from acc_testkit.mcp_client.streamable_http import McpStreamableHttpTestClient


@dataclass(frozen=True, slots=True)
class GatewayRawMcpSessionOwnerProbe:
    """Status-only evidence from the dedicated raw MCP owner-boundary probe."""

    post_status: int
    get_status: int
    delete_status: int

    @property
    def rejected(self) -> bool:
        return (self.post_status, self.get_status, self.delete_status) == (404, 404, 404)

    def evidence(self) -> dict[str, int]:
        return {
            "POST": self.post_status,
            "GET": self.get_status,
            "DELETE": self.delete_status,
        }


@dataclass(frozen=True, slots=True)
class GatewayLogoutProbe:
    """Status-only evidence that logout revoked the old Gateway token."""

    logout_status: int
    old_token_status: int

    @property
    def session_revoked(self) -> bool:
        return self.logout_status == 204

    @property
    def old_token_rejected(self) -> bool:
        return self.old_token_status == 401


class _BorrowedTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        self._transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        """The caller retains ownership of the injected transport."""


class GatewaySessionClient:
    """Own one login token while exposing only secret-safe public values."""

    def __init__(
        self,
        gateway_url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.gateway_url = _validated_gateway_url(gateway_url)
        self.transport = transport
        self._state: Literal["idle", "active"] = "idle"
        self._http: httpx.AsyncClient | None = None
        self._token: SecretValue | None = None

    def __repr__(self) -> str:
        return f"GatewaySessionClient(gateway_url={self.gateway_url!r}, state={self._state!r})"

    async def __aenter__(self) -> GatewaySessionClient:
        if self._state != "idle":
            raise RuntimeError("Gateway session client is already open")
        borrowed = _BorrowedTransport(self.transport) if self.transport is not None else None
        self._http = httpx.AsyncClient(
            transport=borrowed,
            headers={"Origin": self.gateway_url},
            cookies=None,
            auth=None,
            follow_redirects=False,
        )
        self._state = "active"
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        http = self._http
        self._http = None
        self._token = None
        self._state = "idle"
        if http is not None:
            await http.aclose()

    @staticmethod
    def _validate_credentials(identity: SecretValue, password: SecretValue) -> None:
        if not isinstance(identity, SecretValue) or not isinstance(password, SecretValue):
            raise TypeError("identity and password must be SecretValue instances")

    async def login(self, *, identity: SecretValue, password: SecretValue) -> SecretValue:
        self._validate_credentials(identity, password)
        http = self._active_http()
        raw_identity = identity.get_secret_value()
        raw_password = password.get_secret_value()
        response: httpx.Response | None = None
        request_failed = False
        try:
            response = await http.post(
                f"{self.gateway_url}/runtime/sessions",
                json={"identity": raw_identity, "password": raw_password},
            )
        except Exception:
            request_failed = True
        finally:
            raw_identity = ""
            raw_password = ""
        if request_failed:
            raise RuntimeError("Gateway session login failed") from None
        assert response is not None
        if response.status_code != 201:
            del response
            raise RuntimeError("Gateway session login failed") from None
        try:
            payload = response.json()
            raw_token = payload.get("token") if isinstance(payload, dict) else None
            if not isinstance(raw_token, str) or not raw_token:
                raise ValueError
            token = SecretValue(raw_token)
            self._token = token
            return token
        except Exception:
            raise RuntimeError("Gateway session login returned an invalid response") from None
        finally:
            if isinstance(locals().get("payload"), dict):
                payload.clear()
            raw_token = ""
            del response

    async def runtime_info(self) -> GatewayRuntimeInfo:
        response = await self._authorized_request("GET", "/runtime/info")
        if response.status_code != 200:
            del response
            raise RuntimeError("Gateway runtime attestation failed") from None
        try:
            return GatewayRuntimeInfo.model_validate_json(response.content)
        except Exception:
            raise RuntimeError("Gateway runtime attestation is invalid") from None
        finally:
            del response

    def mcp_client(self) -> McpStreamableHttpTestClient:
        token = self._active_token()
        return McpStreamableHttpTestClient(
            f"{self.gateway_url}/mcp",
            token,
            transport=self.transport,
        )

    async def probe_raw_mcp_session_owner_rejection(
        self,
        foreign_session_id: str,
    ) -> GatewayRawMcpSessionOwnerProbe:
        """Use raw protocol requests only to prove MCP session ownership enforcement."""

        if (
            not foreign_session_id
            or foreign_session_id != foreign_session_id.strip()
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E for character in foreign_session_id
            )
        ):
            raise ValueError("foreign MCP session id must be an exact visible ASCII value")
        statuses: dict[str, int] = {}
        try:
            for method in ("POST", "GET", "DELETE"):
                probe_headers = {
                    "Mcp-Session-Id": foreign_session_id,
                    "Accept": "application/json, text/event-stream",
                }
                if method == "POST":
                    probe_headers["Content-Type"] = "application/json"
                try:
                    response = await self._authorized_request(
                        method,
                        "/mcp",
                        extra_headers=probe_headers,
                        json_body=(
                            {
                                "jsonrpc": "2.0",
                                "id": "acc-owner-boundary-probe",
                                "method": "tools/list",
                                "params": {},
                            }
                            if method == "POST"
                            else None
                        ),
                    )
                    statuses[method] = response.status_code
                    del response
                finally:
                    probe_headers.clear()
        finally:
            foreign_session_id = ""
        return GatewayRawMcpSessionOwnerProbe(
            post_status=statuses["POST"],
            get_status=statuses["GET"],
            delete_status=statuses["DELETE"],
        )

    async def logout(self) -> GatewayLogoutProbe:
        response = await self._authorized_request("DELETE", "/runtime/sessions/current")
        logout_status = response.status_code
        del response
        response = await self._authorized_request("GET", "/runtime/info")
        old_token_status = response.status_code
        del response
        self._token = None
        return GatewayLogoutProbe(
            logout_status=logout_status,
            old_token_status=old_token_status,
        )

    async def _authorized_request(
        self,
        method: str,
        path: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
        json_body: Any | None = None,
    ) -> httpx.Response:
        http = self._active_http()
        token = self._active_token()
        raw_token = token.get_secret_value()
        response: httpx.Response | None = None
        request_failed = False
        request_headers = {"Authorization": f"Bearer {raw_token}"}
        if extra_headers is not None:
            request_headers.update(extra_headers)
        try:
            if json_body is None:
                response = await http.request(
                    method,
                    f"{self.gateway_url}{path}",
                    headers=request_headers,
                )
            else:
                response = await http.request(
                    method,
                    f"{self.gateway_url}{path}",
                    headers=request_headers,
                    json=json_body,
                )
        except Exception:
            request_failed = True
        finally:
            raw_token = ""
            request_headers.clear()
        if request_failed:
            raise RuntimeError("Gateway request failed") from None
        assert response is not None
        return response

    def _active_http(self) -> httpx.AsyncClient:
        if self._http is None or self._state != "active":
            raise RuntimeError("Gateway session client is not open")
        return self._http

    def _active_token(self) -> SecretValue:
        if self._token is None:
            raise RuntimeError("Gateway session client is not logged in")
        return self._token


def _validated_gateway_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Gateway base URL must be an absolute HTTP(S) origin")
    return f"{parsed.scheme}://{parsed.netloc}"


__all__ = ["GatewayLogoutProbe", "GatewayRawMcpSessionOwnerProbe", "GatewaySessionClient"]
