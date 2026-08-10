from __future__ import annotations

from typing import Literal, cast

import pytest
from pydantic import ValidationError

from acc_core.models.actions import (
    BodyInjectionTargetV2,
    BodyTokenSourceV2,
    ConcurrencyContractV2,
    HeaderInjectionTargetV2,
    HttpOperationV2,
    HttpSuccessV2,
    IdempotencyContractV2,
    JsonRequestV2,
    OperationSafetyV2,
    ResponseHeaderTokenSourceV2,
    RetryContractV2,
)


def _read_safety() -> OperationSafetyV2:
    return OperationSafetyV2(
        effect="read",
        risk="low",
        reversibility="reversible",
        retry=RetryContractV2(mode="idempotent_only"),
        idempotency=IdempotencyContractV2(mode="unsupported"),
        concurrency=ConcurrencyContractV2(mode="not_supported"),
    )


def _action_safety(**updates: object) -> OperationSafetyV2:
    values: dict[str, object] = {
        "effect": "transition",
        "risk": "high",
        "reversibility": "irreversible",
        "retry": {"mode": "idempotent_only"},
        "idempotency": {
            "mode": "source_key",
            "target": {"kind": "header", "name": "Idempotency-Key"},
        },
        "concurrency": {
            "mode": "required",
            "token": {"kind": "response_header", "name": "ETag"},
            "precondition": {"kind": "header", "name": "If-Match"},
        },
    }
    values.update(updates)
    return OperationSafetyV2.model_validate(values)


def test_public_literal_contracts_are_strict() -> None:
    safety = _action_safety()

    assert safety.effect == "transition"
    assert safety.risk == "high"
    assert safety.reversibility == "irreversible"
    assert safety.retry.mode == "idempotent_only"

    for field, invalid in (
        ("effect", "write"),
        ("risk", "irreversible"),
        ("reversibility", "high"),
    ):
        with pytest.raises(ValidationError):
            _action_safety(**{field: invalid})


def test_operation_safety_requires_every_contract_explicitly() -> None:
    complete = _action_safety().model_dump(mode="python")

    for required in (
        "effect",
        "risk",
        "reversibility",
        "retry",
        "idempotency",
        "concurrency",
    ):
        incomplete = dict(complete)
        incomplete.pop(required)
        with pytest.raises(ValidationError):
            OperationSafetyV2.model_validate(incomplete)


def test_idempotency_source_key_requires_one_runtime_injection_target() -> None:
    header = IdempotencyContractV2(
        mode="source_key",
        target=HeaderInjectionTargetV2(kind="header", name="Idempotency-Key"),
    )
    body = IdempotencyContractV2(
        mode="source_key",
        target=BodyInjectionTargetV2(kind="body", pointer="/request_id"),
    )

    assert header.target is not None
    assert body.target is not None
    assert header.target.kind == "header"
    assert body.target.kind == "body"

    with pytest.raises(ValidationError, match="target is required"):
        IdempotencyContractV2(mode="source_key")
    for mode in ("unsupported", "runtime_deduplicate"):
        with pytest.raises(ValidationError, match="target is not allowed"):
            IdempotencyContractV2(
                mode=mode,
                target=HeaderInjectionTargetV2(kind="header", name="Idempotency-Key"),
            )


def test_idempotent_retry_requires_source_idempotency() -> None:
    with pytest.raises(ValidationError, match="source_key"):
        _action_safety(
            idempotency={"mode": "runtime_deduplicate"},
            retry={"mode": "idempotent_only"},
        )

    safety = _action_safety(
        idempotency={"mode": "runtime_deduplicate"},
        retry={"mode": "never"},
    )
    assert safety.retry.mode == "never"


def test_required_concurrency_needs_token_and_precondition() -> None:
    header_token = ConcurrencyContractV2(
        mode="required",
        token=ResponseHeaderTokenSourceV2(kind="response_header", name="ETag"),
        precondition=HeaderInjectionTargetV2(kind="header", name="If-Match"),
    )
    body_token = ConcurrencyContractV2(
        mode="required",
        token=BodyTokenSourceV2(kind="body", pointer="/version"),
        precondition=BodyInjectionTargetV2(kind="body", pointer="/version"),
    )
    assert header_token.token is not None
    assert body_token.token is not None
    assert header_token.token.kind == "response_header"
    assert body_token.token.kind == "body"

    for missing in ("token", "precondition"):
        values = {
            "mode": "required",
            "token": {"kind": "body", "pointer": "/version"},
            "precondition": {"kind": "header", "name": "If-Match"},
        }
        values.pop(missing)
        with pytest.raises(ValidationError, match="required"):
            ConcurrencyContractV2.model_validate(values)

    with pytest.raises(ValidationError, match="not allowed"):
        ConcurrencyContractV2(
            mode="not_supported",
            token=BodyTokenSourceV2(kind="body", pointer="/version"),
        )


@pytest.mark.parametrize(
    "name",
    [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Host",
        "Content-Length",
        "Transfer-Encoding",
    ],
)
def test_runtime_injection_rejects_transport_and_credential_headers(name: str) -> None:
    with pytest.raises(ValidationError, match="forbidden"):
        HeaderInjectionTargetV2(kind="header", name=name)


@pytest.mark.parametrize("pointer", ["version", "#/version", "/bad~2escape", ""])
def test_body_bindings_require_absolute_rfc6901_pointers(pointer: str) -> None:
    with pytest.raises(ValidationError):
        BodyInjectionTargetV2(kind="body", pointer=pointer)


def test_json_request_and_success_contracts_are_bounded_and_deterministic() -> None:
    request = JsonRequestV2(
        kind="json",
        body_parameters={"/comment": "comment", "/payload": "payload"},
        max_request_bytes=65_536,
    )
    success = HttpSuccessV2(statuses=[200, 202, 204], body="json_or_empty")

    assert request.max_request_bytes == 65_536
    assert success.statuses == [200, 202, 204]

    with pytest.raises(ValidationError):
        JsonRequestV2(kind="json", body_parameters={}, max_request_bytes=0)
    with pytest.raises(ValidationError, match="unique"):
        HttpSuccessV2(statuses=[200, 200], body="json")
    with pytest.raises(ValidationError, match="sorted"):
        HttpSuccessV2(statuses=[204, 200], body="json_or_empty")
    with pytest.raises(ValidationError):
        HttpSuccessV2(statuses=[302], body="empty")


def test_http_v2_accepts_evidenced_json_action_contract() -> None:
    operation = HttpOperationV2(
        method="POST",
        path="/api/orders/{order_id}/approve",
        path_parameters={"order_id": "order_id"},
        query_parameters={},
        request=JsonRequestV2(
            kind="json",
            body_parameters={"/comment": "comment"},
            max_request_bytes=65_536,
        ),
        success=HttpSuccessV2(statuses=[200, 204], body="json_or_empty"),
        scopes=["order.approve"],
        timeout_seconds=15,
        max_response_bytes=1_048_576,
        safety=_action_safety(),
    )

    assert operation.method == "POST"
    assert operation.safety.effect == "transition"
    assert operation.request is not None


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_safe_http_methods_remain_read_only_and_bodyless(method: str) -> None:
    operation = HttpOperationV2(
        method=cast(Literal["GET", "HEAD"], method),
        path="/api/orders/{order_id}",
        path_parameters={"order_id": "order_id"},
        query_parameters={},
        request=None,
        success=HttpSuccessV2(statuses=[200], body="json"),
        scopes=["order.read"],
        timeout_seconds=15,
        max_response_bytes=1_048_576,
        safety=_read_safety(),
    )
    assert operation.safety.effect == "read"

    with pytest.raises(ValidationError, match="GET and HEAD"):
        operation.model_copy(update={"safety": _action_safety()}).__class__.model_validate(
            {**operation.model_dump(mode="python"), "safety": _action_safety()}
        )
    with pytest.raises(ValidationError, match="request body"):
        HttpOperationV2.model_validate(
            {
                **operation.model_dump(mode="python"),
                "request": {
                    "kind": "json",
                    "body_parameters": {},
                    "max_request_bytes": 32,
                },
            }
        )


def test_unsafe_method_declared_read_requires_evidence_classification() -> None:
    document = {
        "method": "POST",
        "path": "/api/search",
        "path_parameters": {},
        "query_parameters": {},
        "request": {
            "kind": "json",
            "body_parameters": {"/query": "query"},
            "max_request_bytes": 4096,
        },
        "success": {"statuses": [200], "body": "json"},
        "scopes": ["search.read"],
        "timeout_seconds": 15,
        "max_response_bytes": 1_048_576,
        "safety": _read_safety().model_dump(mode="python"),
    }

    with pytest.raises(ValidationError, match="evidence classification"):
        HttpOperationV2.model_validate(document)

    operation = HttpOperationV2.model_validate(
        {**document, "unsafe_read_evidence_classification": "documented_side_effect_free"}
    )
    assert operation.safety.effect == "read"


def test_delete_method_cannot_claim_a_nondelete_effect() -> None:
    document = {
        "method": "DELETE",
        "path": "/api/orders/{order_id}",
        "path_parameters": {"order_id": "order_id"},
        "query_parameters": {},
        "request": None,
        "success": {"statuses": [204], "body": "empty"},
        "scopes": ["orders.delete"],
        "timeout_seconds": 15,
        "max_response_bytes": 1024,
        "safety": _action_safety(effect="create").model_dump(mode="python"),
    }

    with pytest.raises(ValidationError, match=r"DELETE.*delete effect"):
        HttpOperationV2.model_validate(document)


def test_http_path_and_placeholders_are_strict() -> None:
    base: dict[str, object] = {
        "method": "GET",
        "path": "/api/orders/{order_id}",
        "path_parameters": {"order_id": "order_id"},
        "query_parameters": {},
        "request": None,
        "success": {"statuses": [200], "body": "json"},
        "scopes": [],
        "timeout_seconds": 15,
        "max_response_bytes": 1024,
        "safety": _read_safety().model_dump(mode="python"),
    }
    with pytest.raises(ValidationError, match="origin-relative"):
        HttpOperationV2.model_validate({**base, "path": "https://evil.test/api"})
    with pytest.raises(ValidationError, match="exactly match"):
        HttpOperationV2.model_validate({**base, "path_parameters": {}})


def test_extra_fields_and_scalar_coercion_are_rejected() -> None:
    with pytest.raises(ValidationError):
        RetryContractV2.model_validate({"mode": "never", "extra": True})
    with pytest.raises(ValidationError):
        HttpSuccessV2.model_validate({"statuses": ["200"], "body": "json"})
