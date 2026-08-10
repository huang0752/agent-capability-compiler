from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import TypeAdapter

from acc_core.contracts import SourceContract
from acc_core.coverage import analyze_coverage
from acc_core.interactions import CapabilityInteractionContract, UIInteractionInventory
from acc_core.interactions.compile import compile_interactions
from acc_core.interactions.validate import analyze_interaction_fidelity
from acc_core.models import Capability, Eval, Operation, Policy, Project
from acc_core.quality import CapabilityQuality
from acc_core.scope import ScopeInventory
from acc_core.validation import ValidationReport

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "interactions"
PROFILES = tuple(sorted(path.parent for path in FIXTURES.glob("*/profile.json")))
INTERACTION_AXES = (
    "surface_disposition",
    "interaction_trace",
    "input_binding_fidelity",
    "default_provenance",
    "option_resolution",
    "condition_coverage",
    "related_data_graph",
    "state_scenarios",
    "presentation_projection",
    "client_adapter_evidence",
)


def _document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _evidence(profile_dir: Path) -> dict[str, object]:
    artifact = profile_dir / "client-artifact.json"
    contents = artifact.read_bytes()
    return {
        "source_id": f"fixture-{profile_dir.name}-client",
        "kind": "source_file",
        "path": artifact.relative_to(ROOT).as_posix(),
        "line_start": 1,
        "line_end": 1,
        "digest": f"sha256:{hashlib.sha256(contents).hexdigest()}",
    }


def _binding(pointer: str, evidence: dict[str, object]) -> dict[str, object]:
    identifier = pointer.removeprefix("/").replace("/", "-")
    return {
        "id": f"input-{identifier}",
        "source_kind": "selected_record" if pointer.endswith("_id") else "user_input",
        "source_id": f"control-{identifier}",
        "source_pointer": pointer,
        "target_pointer": pointer,
        "cardinality": "one",
        "evidence": evidence,
    }


def _default(item: dict[str, Any], evidence: dict[str, object]) -> dict[str, object]:
    target = cast(str, item["target"])
    return {
        "id": f"default-{target.removeprefix('/').replace('/', '-')}",
        "target_pointer": target,
        "source_kind": "literal",
        "value": item["value"],
        "authority": "implementation",
        "precedence": "caller_over_default",
        "submission": "send",
        "override_policy": "caller_allowed",
        "evidence": evidence,
    }


def _option(pointer: str, evidence: dict[str, object]) -> dict[str, object]:
    identifier = pointer.removeprefix("/").replace("/", "-")
    return {
        "id": f"selector-{identifier}",
        "target_pointer": pointer,
        "source_kind": "static",
        "static_options": [{"value": f"{identifier}-value", "label": identifier.title()}],
        "request_bindings": [],
        "value_pointer": "/value",
        "label_pointer": "/label",
        "cascade_dependencies": [],
        "search": {"mode": "none"},
        "pagination": {"mode": "none"},
        "cache": {"mode": "interaction", "max_age_seconds": 60},
        "freshness": "interaction",
        "empty_behavior": "clear_selection",
        "error_behavior": "fail_closed",
        "evidence": evidence,
    }


def _state(state_id: str, evidence: dict[str, object]) -> dict[str, object]:
    return {
        "id": state_id,
        "kind": state_id,
        "allowed_next_events": ["refresh"],
        "evidence": evidence,
    }


def _presentation(item: dict[str, Any], evidence: dict[str, object]) -> dict[str, object]:
    return {
        "id": item["id"],
        "role": item["role"],
        "source_pointer": "/result",
        "field_pointers": item["fields"],
        "ordering": "source",
        "formatting_class": item.get("formatting_class"),
        "pagination": item.get("pagination", "none"),
        "state_ids": item["state_ids"],
        "evidence": evidence,
    }


def _input_schema(profile: dict[str, Any]) -> dict[str, object]:
    pointers = {
        *profile["public_inputs"],
        *(item["target"] for item in profile["defaults"]),
        *profile["selectors"],
        "/trusted_tenant",
    }
    properties: dict[str, object] = {pointer.removeprefix("/"): {} for pointer in sorted(pointers)}
    required = sorted(pointer.removeprefix("/") for pointer in profile["public_inputs"])
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }


def _output_schema(profile: dict[str, Any]) -> dict[str, object]:
    fields = sorted(
        {
            pointer.removeprefix("/")
            for item in profile["presentation"]
            for pointer in item["fields"]
        }
    )
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "result": {
                "type": "object",
                "additionalProperties": False,
                "properties": {field: {} for field in fields},
            }
        },
    }


def _operation(
    profile: dict[str, Any],
    route_id: str,
    index: int,
    evidence: dict[str, object],
) -> Operation:
    method, path = route_id.split(" ", 1)
    action = method not in {"GET", "HEAD"}
    properties = cast(dict[str, object], _input_schema(profile)["properties"])
    path_parameters = {
        parameter: parameter
        for parameter in re.findall(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}", path)
        if parameter in properties
    }
    safety: dict[str, object] = {
        "effect": "transition" if action else "read",
        "risk": "medium" if action else "low",
        "reversibility": "compensatable" if action else "reversible",
        "retry": {"mode": "idempotent_only"},
        "idempotency": (
            {
                "mode": "source_key",
                "target": {"kind": "header", "name": "Idempotency-Key"},
            }
            if action
            else {"mode": "unsupported"}
        ),
        "concurrency": (
            {
                "mode": "required",
                "token": {"kind": "response_header", "name": "ETag"},
                "precondition": {"kind": "header", "name": "If-Match"},
            }
            if action
            else {"mode": "not_supported"}
        ),
    }
    return TypeAdapter(Operation).validate_python(
        {
            "schema_version": "2",
            "kind": "action" if action else "read",
            "id": f"{profile['id']}.operation.{index}",
            "title": f"{profile['id']} operation {index}",
            "input_schema": _input_schema(profile),
            "output_schema": _output_schema(profile),
            "http": {
                "method": method,
                "path": path,
                "path_parameters": path_parameters,
                "query_parameters": {},
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": [f"{profile['id']}.write" if action else f"{profile['id']}.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 65_536,
                "safety": safety,
            },
            "context_bindings": {},
            "evidence": [evidence],
        }
    )


def _capability(profile: dict[str, Any], operations: dict[str, Operation]) -> Capability:
    capability_id = f"{profile['id']}_capability"
    read_ids = [operation.id for operation in operations.values() if operation.kind == "read"]
    action_ids = [operation.id for operation in operations.values() if operation.kind == "action"]
    if not profile["route_ids"]:
        read_ids = []

    def workflow(operation_ids: list[str], *, prepared: bool) -> list[dict[str, object]]:
        if not operation_ids:
            return [{"emit": {"value": {"result": {}}}}]
        steps: list[dict[str, object]] = [
            {
                "id": f"call_{index}",
                "call": {
                    "operation": operation_id,
                    "arguments": {
                        pointer.removeprefix("/"): (
                            f"$.prepared.input.{pointer.removeprefix('/')}"
                            if prepared
                            else f"$.input.{pointer.removeprefix('/')}"
                        )
                        for pointer in profile["public_inputs"]
                    },
                },
            }
            for index, operation_id in enumerate(operation_ids)
        ]
        steps.append({"emit": {"value": f"$.steps.call_{max(len(operation_ids) - 1, 0)}"}})
        return steps

    common: dict[str, object] = {
        "schema_version": "2",
        "id": capability_id,
        "title": f"{profile['id']} capability",
        "description": f"Exercise the {profile['id']} profile.",
        "input_schema": _input_schema(profile),
        "output_schema": _output_schema(profile),
        "policy": f"{profile['id']}-policy",
        "evals": [f"{profile['id']}-success"],
    }
    if profile["action"]:
        document = {
            **common,
            "kind": "action",
            "action": {
                "execution_mode": "single",
                "approval": {"mode": "required"},
                "expires_in_seconds": 300,
            },
            "preview_workflow": workflow(read_ids, prepared=False),
            "commit_workflow": workflow(action_ids, prepared=True),
        }
    else:
        document = {**common, "kind": "read", "workflow": workflow(read_ids, prepared=False)}
    return TypeAdapter(Capability).validate_python(document)


def _documents(profile_dir: Path) -> tuple[ValidationReport, ScopeInventory, dict[str, Any]]:
    profile = _document(profile_dir / "profile.json")
    evidence = _evidence(profile_dir)
    interaction_id = f"{profile['id']}.primary"
    public_bindings = [_binding(pointer, evidence) for pointer in profile["public_inputs"]]
    defaults = [_default(item, evidence) for item in profile["defaults"]]
    options = [_option(pointer, evidence) for pointer in profile["selectors"]]
    states = [_state(state_id, evidence) for state_id in profile["states"]]
    presentation = [_presentation(item, evidence) for item in profile["presentation"]]
    claims: list[dict[str, object]] = [
        {
            "target_pointer": "/interactions/0",
            "evidence": evidence,
            "authority": "implementation",
        }
    ]
    action_lifecycle: dict[str, object] | None = None
    if profile["action"]:
        phases = ("approve", "commit", "prepare", "status")
        claims.extend(
            {
                "target_pointer": f"/interactions/0/lifecycle/{phase}",
                "evidence": evidence,
                "authority": "implementation",
            }
            for phase in phases
        )
        action_lifecycle = {
            "interaction_id": interaction_id,
            **{
                phase: {
                    "target_pointer": f"/interactions/0/lifecycle/{phase}",
                    "evidence": evidence,
                }
                for phase in ("prepare", "approve", "commit", "status")
            },
        }
    interaction = {
        "id": interaction_id,
        "surface_id": profile["surface"],
        "business_intent": f"Exercise the {profile['id']} interaction profile",
        "trigger": {"kind": "screen_load"},
        "route_ids": profile["route_ids"],
        "call_order": profile["call_order"],
        "input_bindings": public_bindings,
        "defaults": defaults,
        "option_sources": options,
        "conditions": [],
        "related_data": [],
        "result_consumption": presentation,
        "states": states,
        "evidence_claims": claims,
        "unknowns": [],
    }
    inventory = UIInteractionInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "complete", "evidence_sources": [evidence["source_id"]]},
            "surfaces": [
                {
                    "id": profile["surface"],
                    "kind": "page",
                    "route_or_entry": f"/{profile['surface']}",
                    "business_purpose": f"Exercise {profile['id']} semantics",
                    "evidence_sources": [evidence["source_id"]],
                }
            ],
            "interactions": [interaction],
            "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
        }
    )
    trusted_binding = {
        "id": "trusted-principal",
        "source_kind": "trusted_context",
        "source_id": "INTERNAL_PRINCIPAL_SENTINEL",
        "source_pointer": "/INTERNAL_TENANT_SENTINEL",
        "target_pointer": "/trusted_tenant",
        "cardinality": "one",
        "evidence": evidence,
    }
    contract = CapabilityInteractionContract.model_validate(
        {
            "schema_version": "2",
            "capability_id": f"{profile['id']}_capability",
            "interaction_ids": [interaction_id],
            "public_input_bindings": public_bindings,
            "trusted_input_bindings": [trusted_binding],
            "defaults": defaults,
            "option_sources": options,
            "conditions": [],
            "related_data": [],
            "result_consumption": presentation,
            "required_scenarios": profile["required_scenarios"],
            "omissions": [],
            "action_lifecycle": action_lifecycle,
        }
    )
    routes = [
        {
            "id": route_id,
            "domain": profile["id"],
            "method": route_id.split(" ", 1)[0],
            "kind": "action" if route_id.startswith("POST ") else "read",
            "effect": "transition" if route_id.startswith("POST ") else "read",
            "path": route_id.split(" ", 1)[1],
            "evidence_sources": [evidence["source_id"]],
            "usage_evidence_sources": [evidence["source_id"]],
            "interaction_ids": [interaction_id],
            "eligibility": "eligible",
            "disposition": "composed",
            "operation_id": f"{profile['id']}.operation.{index}",
            "capability_ids": [contract.capability_id],
        }
        for index, route_id in enumerate(profile["route_ids"])
    ]
    scope = ScopeInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": [profile["id"]]},
            "domains": [{"id": profile["id"], "status": "selected"}],
            "routes": routes,
            "summary": {
                "discovered_routes": len(routes),
                "eligible_routes": len(routes),
                "planned": 0,
                "composed": len(routes),
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        }
    )
    backend_route_ids = profile["route_ids"] or [f"GET /{profile['id']}/artifact-boundary"]
    operations = {
        operation.id: operation
        for index, route_id in enumerate(backend_route_ids)
        for operation in [_operation(profile, route_id, index, evidence)]
    }
    capability = _capability(profile, operations)
    output_fields = sorted(
        {
            f"result.{pointer.removeprefix('/')}"
            for item in profile["presentation"]
            for pointer in item["fields"]
        }
    )
    policy = Policy.model_validate(
        {
            "schema_version": "2",
            "id": f"{profile['id']}-policy",
            "required_scopes": sorted(
                {
                    scope_name
                    for operation in operations.values()
                    for scope_name in operation.http.scopes
                }
            ),
            "tenant_mode": "none",
            "readable_fields": output_fields,
            "denied_fields": [],
            "redaction_rules": [],
        }
    )
    evaluation = Eval.model_validate(
        {
            "schema_version": "2",
            "id": f"{profile['id']}-success",
            "capability": capability.id,
            "input": {
                pointer.removeprefix("/"): "fixture-value" for pointer in profile["public_inputs"]
            },
            "fixtures": {},
            "expected_calls": [],
            "expected_output_schema": _output_schema(profile),
            "forbidden_fields": ["INTERNAL_TENANT_SENTINEL"],
        }
    )
    source_contracts: dict[str, SourceContract] = {}
    for operation in operations.values():
        action_semantics: dict[str, object] | None = None
        if operation.kind == "action":
            action_semantics = {
                "method": operation.http.method,
                **operation.http.safety.model_dump(mode="python"),
                "evidence": evidence,
                "authority": "implementation",
            }
        source_contracts[operation.id] = SourceContract.model_validate(
            {
                "schema_version": "2",
                "id": f"{operation.id}.contract",
                "operation_id": operation.id,
                "request_schema": operation.input_schema,
                "response_schema": operation.output_schema,
                "request_completeness": "complete",
                "response_completeness": "complete",
                "provenance": [],
                "action_semantics": action_semantics,
            }
        )
    input_quality: dict[str, dict[str, object]] = {
        pointer.removeprefix("/"): {
            "kind": "resource_selector" if pointer.endswith("_id") else "query",
            **(
                {"resource_type": pointer.removeprefix("/").removesuffix("_id")}
                if pointer.endswith("_id")
                else {}
            ),
            "acquisition": "caller",
        }
        for pointer in profile["public_inputs"]
    }
    quality = CapabilityQuality.model_validate(
        {
            "schema_version": "2",
            "capability_id": capability.id,
            "intent": {
                "action": "transition" if profile["action"] else "inspect",
                "resource_types": [profile["id"]],
            },
            "inputs": input_quality,
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {
                "max_bytes": 65_536,
                "long_text_disclosures": (
                    [
                        {
                            "path": "/result/body",
                            "acknowledged": True,
                            "reason": "The client artifact explicitly renders an article body.",
                        }
                    ]
                    if profile["id"] == "cms"
                    else []
                ),
            },
        }
    )
    project = Project.model_validate(
        {
            "schema_version": "2",
            "project": {"id": f"fixture-{profile['id']}", "version": "2.0.0"},
            "source_workspace": {"path": f"/fixtures/{profile['id']}", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "FIXTURE_BASE_URL"},
            "quality": {"profile": "standard"},
        }
    )
    report = ValidationReport(
        project=project,
        operations=operations,
        capabilities={capability.id: capability},
        source_contracts=source_contracts,
        capability_quality={capability.id: quality},
        policies={policy.id: policy},
        evals={evaluation.id: evaluation},
        ui_interaction_inventory=inventory,
        interaction_contracts={contract.capability_id: contract},
    )
    return report, scope, profile


@pytest.mark.parametrize("profile_dir", PROFILES, ids=lambda path: path.name)
def test_cross_industry_interaction_profiles_validate_compile_and_cover(
    profile_dir: Path,
) -> None:
    report, scope, profile = _documents(profile_dir)
    artifact = _document(profile_dir / "client-artifact.json")

    assert artifact["artifact_kind"] == "client_source_snapshot"
    assert artifact["surface"] == profile["surface"]
    assert report.ui_interaction_inventory is not None
    assert report.project is not None
    fidelity = analyze_interaction_fidelity(
        project=report.project,
        scope_inventory=scope,
        ui_inventory=report.ui_interaction_inventory,
        contracts=report.interaction_contracts,
        capabilities=report.capabilities,
        operations=report.operations,
        policies=report.policies,
    )
    attestation = compile_interactions(report).to_dict()
    coverage = analyze_coverage(report, scope).model_dump(mode="json")
    serialized = json.dumps(attestation, ensure_ascii=False, sort_keys=True)

    assert attestation["schema_version"] == "2"
    assert not [item for item in fidelity.diagnostics if item.severity == "error"]
    assert not [item for item in report.diagnostics if item.severity == "error"]
    assert report.operations and report.capabilities and report.policies
    assert len(cast(str, attestation["digest"])) == 64
    assert all(axis in coverage for axis in INTERACTION_AXES)
    assert coverage["interaction_trace"][
        "client_only_interaction_ids" if not profile["route_ids"] else "traced_interaction_ids"
    ] == [f"{profile['id']}.primary"]
    assert coverage["client_adapter_evidence"]["status"] == "not_verified"
    assert "INTERNAL_PRINCIPAL_SENTINEL" not in serialized
    assert "INTERNAL_TENANT_SENTINEL" not in serialized
    assert "client-artifact.json" not in serialized


def test_profiles_preserve_the_distinct_cross_industry_contracts() -> None:
    reports = {profile_dir.name: _documents(profile_dir)[0] for profile_dir in PROFILES}
    compiled = {
        profile_dir.name: compile_interactions(reports[profile_dir.name]).to_dict()
        for profile_dir in PROFILES
    }

    crm = cast(dict[str, Any], cast(dict[str, Any], compiled["crm"]["contracts"])["crm_capability"])
    erp = cast(dict[str, Any], cast(dict[str, Any], compiled["erp"]["contracts"])["erp_capability"])
    finance = cast(
        dict[str, Any],
        cast(dict[str, Any], compiled["finance"]["contracts"])["finance_capability"],
    )

    assert crm["inherited_interactions"]["crm.primary"]["call_order"] == "sequential"
    assert erp["action_lifecycle"] == {
        "interaction_id": "erp.primary",
        "phases": ["prepare", "approve", "commit", "status"],
    }
    erp_contract = reports["erp"].interaction_contracts["erp_capability"]
    assert [item.target_pointer for item in erp_contract.public_input_bindings] == ["/order_id"]
    assert reports["erp"].capabilities["erp_capability"].kind == "action"
    assert any(operation.kind == "action" for operation in reports["erp"].operations.values())
    assert any(
        contract.action_semantics is not None
        for contract in reports["erp"].source_contracts.values()
    )
    assert len(finance["option_sources"]) == 3
    assert len({item["target_pointer"] for item in finance["option_sources"]}) == 3
    crm_inventory = reports["crm"].ui_interaction_inventory
    monitoring_inventory = reports["monitoring"].ui_interaction_inventory
    mobile_inventory = reports["mobile"].ui_interaction_inventory
    assert crm_inventory is not None
    assert monitoring_inventory is not None
    assert mobile_inventory is not None
    assert crm_inventory.interactions[0].route_ids == [
        "GET /customers",
        "GET /customers/{customer_id}",
    ]
    assert [item.kind for item in monitoring_inventory.interactions[0].states] == [
        "ready",
        "stale",
    ]
    assert mobile_inventory.interactions[0].route_ids == []
    cms_contract = reports["cms"].interaction_contracts["cms_capability"]
    permission_contract = reports["permissions"].interaction_contracts["permissions_capability"]
    assert cms_contract.result_consumption[0].formatting_class == "long_text"
    assert permission_contract.result_consumption[0].pagination == "server"
