from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from acc_core.contracts import SchemaProvenance, SourceContract


def _evidence() -> dict[str, object]:
    return {
        "source_id": "crm-openapi",
        "kind": "openapi",
        "path": "openapi.json",
        "json_pointer": "/components/schemas/Customer",
        "digest": f"sha256:{'a' * 64}",
    }


def _contract_document() -> dict[str, object]:
    return {
        "schema_version": "2",
        "id": "crm.get_customer.contract",
        "operation_id": "crm.get_customer",
        "request_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["customer_id"],
            "properties": {"customer_id": {"type": "string"}},
        },
        "response_schema": {
            "$defs": {
                "node": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string"},
                        "child": {
                            "anyOf": [
                                {"$ref": "#/$defs/node"},
                                {"type": "null"},
                            ]
                        },
                    },
                }
            },
            "$ref": "#/$defs/node",
        },
        "request_completeness": "complete",
        "response_completeness": "partial",
        "provenance": [
            {
                "target_pointer": "/response_schema/$defs/node/properties/id/type",
                "evidence": _evidence(),
                "evidence_schema_pointer": "/components/schemas/Customer/properties/id/type",
                "authority": "contract",
            }
        ],
    }


def _action_semantics() -> dict[str, object]:
    return {
        "method": "POST",
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
        "evidence": _evidence(),
        "authority": "contract",
    }


@pytest.mark.parametrize("authority", ["contract", "implementation", "test"])
def test_action_semantics_accepts_only_trusted_authorities(authority: str) -> None:
    document = _contract_document()
    semantics = _action_semantics()
    semantics["authority"] = authority
    document["action_semantics"] = semantics

    contract = SourceContract.model_validate(document)

    assert contract.action_semantics is not None
    assert contract.action_semantics.authority == authority


def test_action_semantics_rejects_observation_authority() -> None:
    document = _contract_document()
    semantics = _action_semantics()
    semantics["authority"] = "observation"
    document["action_semantics"] = semantics

    with pytest.raises(ValidationError, match=r"contract.*implementation.*test"):
        SourceContract.model_validate(document)


def test_source_contract_accepts_complete_optional_action_semantics() -> None:
    document = _contract_document()
    document["action_semantics"] = _action_semantics()

    contract = SourceContract.model_validate(document)

    assert contract.action_semantics is not None
    assert contract.action_semantics.method == "POST"
    assert contract.action_semantics.idempotency.mode == "source_key"
    assert contract.action_semantics.concurrency.mode == "required"


@pytest.mark.parametrize("authority", ["contract", "implementation", "test", "observation"])
def test_source_contract_accepts_all_provenance_authority_levels(authority: str) -> None:
    document = _contract_document()
    provenance = deepcopy(document["provenance"])
    assert isinstance(provenance, list)
    assert isinstance(provenance[0], dict)
    provenance[0]["authority"] = authority
    document["provenance"] = provenance

    contract = SourceContract.model_validate(document)

    assert contract.provenance[0].authority == authority


def test_source_contract_accepts_recursive_draft_2020_12_schemas() -> None:
    contract = SourceContract.model_validate(_contract_document())

    assert contract.response_schema["$ref"] == "#/$defs/node"
    assert contract.request_completeness == "complete"
    assert contract.response_completeness == "partial"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_pointer", "response_schema/properties/id"),
        ("target_pointer", "/response_schema/~2invalid"),
        ("evidence_schema_pointer", "components/schemas/Customer"),
        ("evidence_schema_pointer", "/components/~invalid"),
    ],
)
def test_schema_provenance_rejects_invalid_json_pointers(field: str, value: str) -> None:
    document = _contract_document()
    provenance = deepcopy(document["provenance"])
    assert isinstance(provenance, list)
    assert isinstance(provenance[0], dict)
    provenance[0][field] = value

    with pytest.raises(ValidationError, match="RFC 6901"):
        SchemaProvenance.model_validate(provenance[0])


def test_source_contract_rejects_a_provenance_target_that_does_not_exist() -> None:
    document = _contract_document()
    provenance = deepcopy(document["provenance"])
    assert isinstance(provenance, list)
    assert isinstance(provenance[0], dict)
    provenance[0]["target_pointer"] = "/response_schema/$defs/node/properties/missing/type"
    document["provenance"] = provenance

    with pytest.raises(ValidationError, match="target_pointer does not exist"):
        SourceContract.model_validate(document)


def test_source_contract_rejects_targets_outside_request_or_response_schema() -> None:
    document = _contract_document()
    provenance = deepcopy(document["provenance"])
    assert isinstance(provenance, list)
    assert isinstance(provenance[0], dict)
    provenance[0]["target_pointer"] = "/operation_id"
    document["provenance"] = provenance

    with pytest.raises(ValidationError, match="request_schema or response_schema"):
        SourceContract.model_validate(document)


def test_source_contract_rejects_duplicate_provenance_claim_identities() -> None:
    document = _contract_document()
    provenance = deepcopy(document["provenance"])
    assert isinstance(provenance, list)
    provenance.append(deepcopy(provenance[0]))
    document["provenance"] = provenance

    with pytest.raises(ValidationError, match="duplicate provenance claim"):
        SourceContract.model_validate(document)


def test_source_contract_is_strict_and_requires_schema_version_two() -> None:
    extra_document = _contract_document()
    extra_document["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SourceContract.model_validate(extra_document)

    old_document = _contract_document()
    old_document["schema_version"] = "1"
    with pytest.raises(ValidationError, match="Input should be '2'"):
        SourceContract.model_validate(old_document)


def test_source_contract_json_schema_generation_is_stable() -> None:
    first = SourceContract.model_json_schema(mode="validation")
    second = SourceContract.model_json_schema(mode="validation")

    assert first == second
    assert first["additionalProperties"] is False
    assert first["properties"]["schema_version"] == {
        "const": "2",
        "title": "Schema Version",
        "type": "string",
    }
    assert "SchemaProvenance" in first["$defs"]
