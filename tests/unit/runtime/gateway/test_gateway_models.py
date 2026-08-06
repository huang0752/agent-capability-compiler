from __future__ import annotations

import pytest
from pydantic import ValidationError

from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway.models import (
    GatewaySessionCreation,
    GatewaySessionRecord,
    GatewaySessionStatus,
    GatewaySettings,
    SessionCreateRequest,
    SessionCreateResponse,
)


def _context() -> PrincipalContext:
    return PrincipalContext(
        principal_id="user-a",
        gateway_session_id="session-a",
        target_system_id="system-a",
        source_scopes={"read"},
        deployment_scope_ceiling={"documents.read"},
        scope_mapping={"read": {"documents.read"}},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle="auth-a",
    )


def test_gateway_settings_defaults_and_accepts_exact_allowlists() -> None:
    settings = GatewaySettings(
        allowed_hosts=("gateway.example.com", "gateway.example.com:8443"),
        allowed_origins=("https://agent.example.com",),
    )

    assert settings.session_ttl_seconds == 3600
    assert settings.max_sessions == 1000
    assert settings.listen_host == "127.0.0.1"
    assert settings.listen_port == 8000
    assert settings.worker_count == 1
    assert settings.allowed_hosts == (
        "gateway.example.com",
        "gateway.example.com:8443",
    )


@pytest.mark.parametrize("ttl", [0, 86401])
def test_gateway_settings_rejects_ttl_outside_safe_range(ttl: int) -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(allowed_hosts=("localhost",), session_ttl_seconds=ttl)


def test_gateway_settings_rejects_nonpositive_capacity() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(allowed_hosts=("localhost",), max_sessions=0)


@pytest.mark.parametrize("listen_port", [0, 65536])
def test_gateway_settings_rejects_invalid_listener_port(listen_port: int) -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(allowed_hosts=("localhost",), listen_port=listen_port)


def test_gateway_settings_rejects_multiple_workers() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(allowed_hosts=("localhost",), worker_count=2)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allowed_hosts", ()),
        ("allowed_hosts", ("*",)),
        ("allowed_hosts", ("https://gateway.example.com",)),
        ("allowed_hosts", ("user@gateway.example.com",)),
        ("allowed_hosts", ("gateway.example.com/path",)),
        ("allowed_origins", ("*",)),
        ("allowed_origins", ("https://user:secret@agent.example.com",)),
        ("allowed_origins", ("https://agent.example.com/path",)),
        ("allowed_origins", ("https://agent.example.com?next=/x",)),
        ("allowed_origins", ("https://agent.example.com/#fragment",)),
    ],
)
def test_gateway_settings_rejects_ambiguous_or_wildcard_allowlist_entries(
    field: str,
    value: tuple[str, ...],
) -> None:
    values: dict[str, object] = {"allowed_hosts": ("localhost",), field: value}
    with pytest.raises(ValidationError):
        GatewaySettings.model_validate(values)


def test_gateway_settings_rejects_plaintext_non_loopback_listener() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(
            listen_host="0.0.0.0",
            tls_enabled=False,
            allowed_hosts=("gateway.example.com",),
        )


def test_gateway_settings_accepts_tls_non_loopback_listener() -> None:
    settings = GatewaySettings(
        listen_host="0.0.0.0",
        tls_enabled=True,
        allowed_hosts=("gateway.example.com",),
    )

    assert settings.listen_host == "0.0.0.0"


def test_session_create_request_only_accepts_identity_and_password() -> None:
    request = SessionCreateRequest.model_validate(
        {"identity": "a@example.com", "password": "top-secret"}
    )

    assert request.identity == "a@example.com"
    assert request.password.get_secret_value() == "top-secret"
    assert "a@example.com" not in repr(request)
    assert "top-secret" not in repr(request)
    assert request.model_dump() == {}
    assert request.model_dump_json() == "{}"

    with pytest.raises(ValidationError):
        SessionCreateRequest.model_validate(
            {"identity": "a@example.com", "password": "secret", "scopes": ["admin"]}
        )


@pytest.mark.parametrize(
    "invalid_values",
    [
        {"identity": "", "password": "validation-password-secret"},
        {"identity": "a@example.com", "password": "", "unexpected": True},
    ],
)
def test_session_create_validation_errors_never_echo_password(
    invalid_values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError) as caught:
        SessionCreateRequest.model_validate(invalid_values)

    assert "validation-password-secret" not in str(caught.value)


@pytest.mark.parametrize(
    "malformed_password",
    [
        {"value": "nested-password-secret"},
        ["nested-password-secret"],
    ],
)
def test_malformed_password_type_is_redacted_from_every_validation_view(
    malformed_password: object,
) -> None:
    with pytest.raises(ValidationError) as caught:
        SessionCreateRequest.model_validate(
            {"identity": "a@example.com", "password": malformed_password}
        )

    assert "nested-password-secret" not in str(caught.value)
    assert "nested-password-secret" not in str(caught.value.errors())
    assert "nested-password-secret" not in caught.value.json()


@pytest.mark.parametrize(
    "malformed_identity",
    [
        {"value": "nested-identity-secret"},
        ["nested-identity-secret"],
        " identity-whitespace-secret ",
        "identity-surrogate-secret-\ud800",
    ],
)
def test_invalid_identity_is_redacted_from_every_validation_view(
    malformed_identity: object,
) -> None:
    with pytest.raises(ValidationError) as caught:
        SessionCreateRequest.model_validate(
            {"identity": malformed_identity, "password": "valid-password"}
        )

    for rendered in (
        str(caught.value),
        repr(caught.value),
        str(caught.value.args),
        str(caught.value.errors()),
        caught.value.json(),
    ):
        assert "nested-identity-secret" not in rendered
        assert "identity-whitespace-secret" not in rendered
        assert "identity-surrogate-secret" not in rendered


def test_session_response_secret_is_one_shot_and_not_publicly_serialized() -> None:
    response = SessionCreateResponse.model_validate(
        {"gateway_token": "gateway-token-secret", "expires_in_seconds": 120}
    )

    assert response.gateway_token.get_secret_value() == "gateway-token-secret"
    assert "gateway-token-secret" not in repr(response)
    assert response.model_dump() == {"expires_in_seconds": 120}
    assert response.one_time_payload() == {
        "token": "gateway-token-secret",
        "expires_in_seconds": 120,
    }


def test_gateway_session_record_hides_internal_identity_and_tokens() -> None:
    record = GatewaySessionRecord(
        session_id="session-a",
        token_digest="a" * 64,
        principal_context=_context(),
        created_at=10.0,
        expires_at=20.0,
        status=GatewaySessionStatus.ACTIVE,
    )

    rendered = repr(record)
    serialized = record.model_dump()
    assert "user-a" not in rendered
    assert "a" * 64 not in rendered
    assert "user-a" not in str(serialized)
    assert "a" * 64 not in str(serialized)
    assert serialized == {
        "session_id": "session-a",
        "created_at": 10.0,
        "expires_at": 20.0,
        "status": GatewaySessionStatus.ACTIVE,
    }


def test_gateway_session_record_defensively_keeps_immutable_context() -> None:
    tenant = {"tenant_id": "tenant-a", "nested": {"region": "east"}}
    context = PrincipalContext(
        principal_id="user-a",
        gateway_session_id="session-a",
        target_system_id="system-a",
        source_scopes={"read"},
        deployment_scope_ceiling={"documents.read"},
        scope_mapping={"read": {"documents.read"}},
        tenant_context=tenant,
        auth_state_handle="auth-a",
    )
    record = GatewaySessionRecord(
        session_id="session-a",
        token_digest="a" * 64,
        principal_context=context,
        created_at=10.0,
        expires_at=20.0,
    )
    tenant["tenant_id"] = "tenant-b"
    nested = tenant["nested"]
    assert isinstance(nested, dict)
    nested["region"] = "west"

    assert record.principal_context.tenant_context == {
        "tenant_id": "tenant-a",
        "nested": {"region": "east"},
    }


def test_gateway_session_creation_is_redacted_and_keeps_removed_generations() -> None:
    record_a = GatewaySessionRecord(
        session_id="session-a",
        token_digest="a" * 64,
        principal_context=_context(),
        created_at=10.0,
        expires_at=20.0,
    )
    record_b = record_a.model_copy(update={"token_digest": "b" * 64})
    creation = GatewaySessionCreation(
        token=SecretValue("gateway-token-secret"),
        record=record_b,
        removed_records=(record_a,),
    )

    token, record = creation
    assert token.get_secret_value() == "gateway-token-secret"
    assert record == record_b
    assert creation.removed_records == (record_a,)
    assert "gateway-token-secret" not in repr(creation)


@pytest.mark.parametrize(
    "host",
    [
        "example.com:",
        "[::1]:",
        "exa mple.com",
        ".example.com",
        "example..com",
        "-example.com",
        "example-.com",
        "example.com:0",
        "example.com:65536",
    ],
)
def test_gateway_settings_rejects_invalid_exact_host_authority(host: str) -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(allowed_hosts=(host,))


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.com:",
        "https://[::1]:",
        "https://exa mple.com",
        "https://.example.com",
        "https://example..com",
        "https://example.com:0",
        "https://example.com:65536",
    ],
)
def test_gateway_settings_rejects_invalid_exact_origin_authority(origin: str) -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(allowed_hosts=("localhost",), allowed_origins=(origin,))


def test_gateway_settings_normalizes_dns_ipv6_and_default_origin_ports() -> None:
    settings = GatewaySettings(
        allowed_hosts=("EXAMPLE.COM:8443", "[0:0:0:0:0:0:0:1]:8443"),
        allowed_origins=("HTTPS://EXAMPLE.COM:443", "http://[0:0:0:0:0:0:0:1]:80"),
    )

    assert settings.allowed_hosts == ("example.com:8443", "[::1]:8443")
    assert settings.allowed_origins == ("https://example.com", "http://[::1]")
