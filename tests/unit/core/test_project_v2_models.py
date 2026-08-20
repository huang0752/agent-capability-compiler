from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from acc_core.models import (
    Capability,
    CapabilityV2,
    JsonPointerApplicationSuccessConfig,
    Operation,
    OperationV2,
    Project,
    ProjectDocument,
    ProjectV2,
)
from acc_core.schemas import MODEL_SCHEMAS


def _project(version: str = "2") -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": version,
        "project": {"id": "orders", "version": "2.0.0"},
        "source_workspace": {"path": "/srv/orders", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "ORDERS_BASE_URL",
            "auth": {"kind": "bearer_secret", "token_ref": "ORDERS_TOKEN"},
        },
    }
    if version == "2":
        document["quality"] = {"profile": "standard"}
    return document


def test_project_document_accepts_only_the_current_format() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        TypeAdapter(ProjectDocument).validate_python(_project("1"))

    current = TypeAdapter(ProjectDocument).validate_python(_project("2"))

    assert isinstance(current, Project)
    assert Project is ProjectV2
    assert TypeAdapter(Operation).json_schema() == TypeAdapter(OperationV2).json_schema()
    assert TypeAdapter(Capability).json_schema() == TypeAdapter(CapabilityV2).json_schema()
    assert current.quality.profile == "standard"


def test_project_v2_requires_an_explicit_quality_profile() -> None:
    document = _project()
    document.pop("quality")

    with pytest.raises(ValidationError, match="quality"):
        ProjectV2.model_validate(document)


def test_project_provider_accepts_a_json_pointer_application_success_contract() -> None:
    document = _project()
    document["provider"]["application_success"] = {
        "kind": "json_pointer",
        "pointer": "/code",
        "allowed_values": [200, "OK", True, None],
    }

    project = ProjectV2.model_validate(document)

    assert project.provider.application_success == JsonPointerApplicationSuccessConfig(
        kind="json_pointer",
        pointer="/code",
        allowed_values=[200, "OK", True, None],
    )
    assert project.model_dump(mode="json")["provider"]["application_success"] == {
        "kind": "json_pointer",
        "pointer": "/code",
        "allowed_values": [200, "OK", True, None],
    }


@pytest.mark.parametrize(
    "allowed_values",
    [[], [[200]], [{"code": 200}], [float("nan")], [200, 200]],
)
def test_project_provider_rejects_invalid_application_success_values(
    allowed_values: list[object],
) -> None:
    document = _project()
    document["provider"]["application_success"] = {
        "kind": "json_pointer",
        "pointer": "/code",
        "allowed_values": allowed_values,
    }

    with pytest.raises(ValidationError, match="allowed_values"):
        ProjectV2.model_validate(document)


def test_application_success_values_use_type_exact_uniqueness() -> None:
    document = _project()
    document["provider"]["application_success"] = {
        "kind": "json_pointer",
        "pointer": "/code",
        "allowed_values": [1, True, 1.0],
    }

    project = ProjectV2.model_validate(document)

    values = project.provider.application_success.allowed_values
    assert [(type(value), value) for value in values] == [
        (int, 1),
        (bool, True),
        (float, 1.0),
    ]


def test_schema_exports_use_only_canonical_current_names() -> None:
    assert set(MODEL_SCHEMAS) == {
        "capability",
        "capability-candidates",
        "capability-quality",
        "domain-change-request",
        "domain-decision",
        "domain-evidence-change-set",
        "domain-map",
        "eval",
        "evidence",
        "interaction-contract",
        "intent-plan",
        "live-observation-artifact",
        "operation",
        "policy",
        "project",
        "scope-inventory",
        "source-contract",
        "ui-interaction-inventory",
        "usage-domain-contract",
        "usage-domain-index",
        "usage-mcp-release-acceptance",
        "usage-project",
        "usage-release",
        "usage-scenario",
        "usage-source-snapshot",
    }
    for name in (
        "capability",
        "capability-quality",
        "eval",
        "operation",
        "policy",
        "project",
        "scope-inventory",
        "source-contract",
    ):
        schema = MODEL_SCHEMAS[name]
        generated = (
            schema.json_schema(mode="validation")
            if isinstance(schema, TypeAdapter)
            else schema.model_json_schema(mode="validation")
        )
        serialized = str(generated)
        assert "'const': '1'" not in serialized
        assert "'const': '2'" in serialized
