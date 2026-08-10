from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from acc_core.cli.main import main as cli_main
from acc_core.compiler import compile_project
from acc_core.models import ProjectV2
from acc_core.packaging import PackFormatError, build_pack, verify_pack
from acc_core.validation import validate_project
from acc_runtime.loader import load_pack


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _evidence() -> dict[str, object]:
    return {
        "source_id": "orders-openapi",
        "kind": "openapi",
        "path": "openapi.json",
        "json_pointer": "/paths/~1orders/get",
        "digest": "sha256:" + "a" * 64,
    }


def _v2_project(tmp_path: Path, *, sidecars: bool = True) -> Path:
    project = tmp_path / "project"
    _write(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "orders", "version": "2.0.0"},
            "source_workspace": {"path": "/srv/orders", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "ORDERS_BASE_URL",
                "auth": {"kind": "bearer_secret", "token_ref": "ORDERS_TOKEN"},
            },
            "quality": {"profile": "standard"},
        },
    )
    _write(
        project / "operations" / "orders.get.yaml",
        {
            "schema_version": "2",
            "kind": "read",
            "id": "orders.get",
            "title": "Get order",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "output_schema": {"type": "object"},
            "http": {
                "method": "GET",
                "path": "/orders/{order_id}",
                "path_parameters": {"order_id": "order_id"},
                "query_parameters": {},
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": ["orders.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 1048576,
                "safety": {
                    "effect": "read",
                    "risk": "low",
                    "reversibility": "reversible",
                    "retry": {"mode": "idempotent_only"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "context_bindings": {},
            "evidence": [_evidence()],
        },
    )
    _write(
        project / "capabilities" / "orders.inspect.yaml",
        {
            "schema_version": "2",
            "kind": "read",
            "id": "orders.inspect",
            "title": "Inspect order",
            "description": "Inspect one order.",
            "input_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "output_schema": {"type": "object"},
            "workflow": [
                {
                    "id": "current",
                    "call": {
                        "operation": "orders.get",
                        "arguments": {"order_id": "$.input.order_id"},
                    },
                },
                {"emit": {"value": "$.steps.current"}},
            ],
            "policy": "orders-read",
            "evals": ["orders-inspect-success"],
        },
    )
    _write(
        project / "policies" / "orders-read.yaml",
        {
            "schema_version": "2",
            "id": "orders-read",
            "required_scopes": ["orders.read"],
            "tenant_mode": "none",
            "tenant_field": None,
            "readable_fields": ["id"],
            "denied_fields": [],
            "redaction_rules": [],
        },
    )
    _write(
        project / "evals" / "orders-inspect-success.yaml",
        {
            "schema_version": "2",
            "id": "orders-inspect-success",
            "capability": "orders.inspect",
            "input": {"order_id": "order-1"},
            "fixtures": {},
            "expected_calls": [{"operation": "orders.get", "arguments": {"order_id": "order-1"}}],
            "expected_output_schema": {"type": "object"},
            "expected_error": None,
            "forbidden_fields": [],
        },
    )
    if sidecars:
        _write(
            project / "source-contracts" / "orders.get.yaml",
            {
                "schema_version": "2",
                "id": "orders.get.contract",
                "operation_id": "orders.get",
                "request_schema": {"type": "object"},
                "response_schema": {"type": "object"},
                "request_completeness": "complete",
                "response_completeness": "complete",
                "provenance": [],
            },
        )
        _write(
            project / "capability-quality" / "orders.inspect.yaml",
            {
                "schema_version": "2",
                "capability_id": "orders.inspect",
                "intent": {"action": "get", "resource_types": ["order"]},
                "inputs": {
                    "order_id": {
                        "kind": "resource_selector",
                        "resource_type": "order",
                        "acquisition": "caller",
                    }
                },
                "composition": {"failure_mode": "fail_fast"},
                "output_budget": {"max_bytes": 65536},
            },
        )
    return project


def _add_action(project: Path) -> None:
    _write(
        project / "operations" / "orders.approve.yaml",
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.approve",
            "title": "Approve order",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "output_schema": {"type": "object"},
            "http": {
                "method": "POST",
                "path": "/orders/{order_id}/approve",
                "path_parameters": {"order_id": "order_id"},
                "query_parameters": {},
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": ["orders.approve"],
                "timeout_seconds": 15,
                "max_response_bytes": 1048576,
                "safety": {
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
                },
            },
            "context_bindings": {},
            "evidence": [_evidence()],
        },
    )
    _write(
        project / "capabilities" / "orders.approve.yaml",
        {
            "schema_version": "2",
            "kind": "action",
            "id": "orders.approve",
            "title": "Approve order",
            "description": "Preview and approve one order.",
            "input_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "output_schema": {"type": "object"},
            "action": {
                "execution_mode": "single",
                "approval": {"mode": "required"},
                "expires_in_seconds": 300,
            },
            "preview_workflow": [
                {
                    "id": "current",
                    "call": {
                        "operation": "orders.get",
                        "arguments": {"order_id": "$.input.order_id"},
                    },
                },
                {"emit": {"value": "$.steps.current"}},
            ],
            "commit_workflow": [
                {
                    "id": "approved",
                    "call": {
                        "operation": "orders.approve",
                        "arguments": {"order_id": "$.prepared.input.order_id"},
                    },
                },
                {"emit": {"value": "$.steps.approved"}},
            ],
            "policy": "orders-read",
            "evals": ["orders-approve-success"],
        },
    )
    _write(
        project / "source-contracts" / "orders.approve.yaml",
        {
            "schema_version": "2",
            "id": "orders.approve.contract",
            "operation_id": "orders.approve",
            "request_schema": {"type": "object"},
            "response_schema": {"type": "object"},
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
            "action_semantics": {
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
            },
        },
    )
    _write(
        project / "capability-quality" / "orders.approve.yaml",
        {
            "schema_version": "2",
            "capability_id": "orders.approve",
            "intent": {"action": "transition", "resource_types": ["order"]},
            "inputs": {
                "order_id": {
                    "kind": "resource_selector",
                    "resource_type": "order",
                    "acquisition": "caller",
                }
            },
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65536},
        },
    )
    _write(
        project / "evals" / "orders-approve-success.yaml",
        {
            "schema_version": "2",
            "id": "orders-approve-success",
            "capability": "orders.approve",
            "input": {"order_id": "order-1"},
            "fixtures": {},
            "expected_calls": [
                {"operation": "orders.get", "arguments": {"order_id": "order-1"}},
                {"operation": "orders.approve", "arguments": {"order_id": "order-1"}},
            ],
            "expected_output_schema": {"type": "object"},
            "expected_error": None,
            "forbidden_fields": [],
        },
    )


def _write_action_interaction_sidecars(project: Path, *, lifecycle: bool) -> None:
    interaction_evidence = _evidence()
    phase_evidence = {
        phase: {**_evidence(), "source_id": f"orders-lifecycle-{phase}"}
        for phase in ("approve", "commit", "prepare", "status")
    }
    inventory_evidence_sources = ["orders-openapi"]
    if lifecycle:
        inventory_evidence_sources.extend(
            sorted(cast(str, item["source_id"]) for item in phase_evidence.values())
        )
        inventory_evidence_sources.sort()
    _write(
        project / "scope-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": ["orders"]},
            "domains": [{"id": "orders", "status": "selected"}],
            "routes": [
                {
                    "id": "GET /orders/{order_id}",
                    "domain": "orders",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/orders/{order_id}",
                    "evidence_sources": ["orders-openapi"],
                    "usage_evidence_sources": ["orders-openapi"],
                    "interaction_ids": ["orders.inspect"],
                    "eligibility": "eligible",
                    "disposition": "planned",
                    "operation_id": "orders.get",
                    "capability_ids": ["orders.inspect"],
                },
                {
                    "id": "POST /orders/{order_id}/approve",
                    "domain": "orders",
                    "method": "POST",
                    "kind": "action",
                    "effect": "transition",
                    "path": "/orders/{order_id}/approve",
                    "evidence_sources": ["orders-openapi"],
                    "usage_evidence_sources": ["orders-openapi"],
                    "interaction_ids": ["orders.approve"],
                    "eligibility": "eligible",
                    "disposition": "planned",
                    "operation_id": "orders.approve",
                    "capability_ids": ["orders.approve"],
                },
            ],
            "summary": {
                "discovered_routes": 2,
                "eligible_routes": 2,
                "planned": 2,
                "composed": 0,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        },
    )
    interactions = []
    for index, (interaction_id, route_id) in enumerate(
        (
            ("orders.approve", "POST /orders/{order_id}/approve"),
            ("orders.inspect", "GET /orders/{order_id}"),
        )
    ):
        interactions.append(
            {
                "id": interaction_id,
                "surface_id": "orders",
                "business_intent": interaction_id,
                "trigger": {"kind": "confirm" if index == 0 else "select"},
                "route_ids": [route_id],
                "call_order": "sequential",
                "input_bindings": [],
                "defaults": [],
                "option_sources": [],
                "conditions": [],
                "related_data": [],
                "result_consumption": [],
                "states": [],
                "evidence_claims": [
                    {
                        "target_pointer": f"/interactions/{index}",
                        "evidence": interaction_evidence,
                        "evidence_pointer": f"/paths/{index}",
                        "authority": "contract",
                    },
                    *(
                        [
                            {
                                "target_pointer": f"/interactions/{index}/lifecycle/{phase}",
                                "evidence": phase_evidence[phase],
                                "evidence_pointer": f"/lifecycle/{phase}",
                                "authority": "contract",
                            }
                            for phase in ("approve", "commit", "prepare", "status")
                        ]
                        if lifecycle and interaction_id == "orders.approve"
                        else []
                    ),
                ],
                "unknowns": [],
            }
        )
    _write(
        project / "ui-interaction-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {
                "mode": "complete",
                "evidence_sources": inventory_evidence_sources,
            },
            "surfaces": [
                {
                    "id": "orders",
                    "kind": "page",
                    "route_or_entry": "/orders",
                    "business_purpose": "Inspect and approve orders",
                    "evidence_sources": inventory_evidence_sources,
                }
            ],
            "interactions": interactions,
            "summary": {"surfaces": 1, "interactions": 2, "unresolved": 0},
        },
    )
    for capability_id, interaction_id in (
        ("orders.approve", "orders.approve"),
        ("orders.inspect", "orders.inspect"),
    ):
        contract: dict[str, object] = {
            "schema_version": "2",
            "capability_id": capability_id,
            "interaction_ids": [interaction_id],
            "public_input_bindings": [],
            "trusted_input_bindings": [],
            "defaults": [],
            "option_sources": [],
            "conditions": [],
            "related_data": [],
            "result_consumption": [],
            "required_scenarios": [f"{interaction_id}.success"],
            "omissions": [],
        }
        if capability_id == "orders.approve" and lifecycle:
            contract["action_lifecycle"] = {
                "interaction_id": interaction_id,
                "prepare": {
                    "target_pointer": "/interactions/0/lifecycle/prepare",
                    "evidence": phase_evidence["prepare"],
                },
                "approve": {
                    "target_pointer": "/interactions/0/lifecycle/approve",
                    "evidence": phase_evidence["approve"],
                },
                "commit": {
                    "target_pointer": "/interactions/0/lifecycle/commit",
                    "evidence": phase_evidence["commit"],
                },
                "status": {
                    "target_pointer": "/interactions/0/lifecycle/status",
                    "evidence": phase_evidence["status"],
                },
            }
        _write(project / "interaction-contracts" / f"{capability_id}.yaml", contract)


def test_unproven_action_interaction_lifecycle_blocks_validation_and_compile(
    tmp_path: Path,
) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)
    _write_action_interaction_sidecars(project, lifecycle=False)

    validation = validate_project(project)
    compilation = compile_project(project)

    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" in {item.code for item in validation.diagnostics}
    assert compilation.ir is None
    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" in {item.code for item in compilation.diagnostics}


def test_proven_action_interaction_lifecycle_reaches_compiler(tmp_path: Path) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)
    _write_action_interaction_sidecars(project, lifecycle=True)

    validation = validate_project(project)
    compilation = compile_project(project)

    assert "ACC_UI_ACTION_LIFECYCLE_REQUIRED" not in {item.code for item in validation.diagnostics}
    assert compilation.ir is not None, compilation.diagnostics


def test_validate_project_loads_a_closed_v2_quality_project(tmp_path: Path) -> None:
    report = validate_project(_v2_project(tmp_path))

    assert report.ok, report.diagnostics
    assert isinstance(report.project, ProjectV2)
    assert set(report.source_contracts) == {"orders.get"}
    assert set(report.capability_quality) == {"orders.inspect"}


@pytest.mark.parametrize(
    "relative_path",
    [
        "project.yaml",
        "operations/orders.get.yaml",
        "capabilities/orders.inspect.yaml",
        "policies/orders-read.yaml",
        "evals/orders-inspect-success.yaml",
    ],
)
def test_validate_project_rejects_every_legacy_top_level_document(
    tmp_path: Path,
    relative_path: str,
) -> None:
    project = _v2_project(tmp_path)
    path = project / relative_path
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["schema_version"] = "1"
    _write(path, document)

    report = validate_project(project)

    diagnostic = next(item for item in report.diagnostics if item.path == relative_path)
    assert diagnostic.code == "ACC_FORMAT_VERSION_UNSUPPORTED"
    assert diagnostic.pointer == "/schema_version"


def test_validate_project_v2_reports_each_missing_quality_sidecar(tmp_path: Path) -> None:
    report = validate_project(_v2_project(tmp_path, sidecars=False))

    assert not report.ok
    assert {item.code for item in report.diagnostics} >= {
        "ACC_SOURCE_CONTRACT_MISSING",
        "ACC_CAPABILITY_QUALITY_MISSING",
    }


def test_validate_project_v2_rejects_provenance_from_unbound_evidence(tmp_path: Path) -> None:
    project = _v2_project(tmp_path)
    path = project / "source-contracts" / "orders.get.yaml"
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    contract["provenance"] = [
        {
            "target_pointer": "/response_schema/type",
            "evidence": {**_evidence(), "digest": "sha256:" + "b" * 64},
            "evidence_schema_pointer": "/components/schemas/Order/type",
            "authority": "contract",
        }
    ]
    _write(path, contract)

    report = validate_project(project)

    assert "ACC_SCHEMA_PROVENANCE_EVIDENCE_MISMATCH" in {item.code for item in report.diagnostics}


def test_validate_project_v2_forbids_action_semantics_for_a_read_operation(
    tmp_path: Path,
) -> None:
    project = _v2_project(tmp_path)
    path = project / "source-contracts" / "orders.get.yaml"
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    contract["action_semantics"] = {
        "method": "POST",
        "effect": "transition",
        "risk": "high",
        "reversibility": "irreversible",
        "retry": {"mode": "never"},
        "idempotency": {"mode": "unsupported"},
        "concurrency": {"mode": "not_supported"},
        "evidence": _evidence(),
        "authority": "contract",
    }
    _write(path, contract)

    report = validate_project(project)

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_ACTION_SEMANTICS_FORBIDDEN"
    )
    assert diagnostic.path == "source-contracts/orders.get.yaml"
    assert diagnostic.pointer == "/action_semantics"


def test_validate_project_v2_requires_action_semantics_for_an_action_operation(
    tmp_path: Path,
) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)
    path = project / "source-contracts" / "orders.approve.yaml"
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    del contract["action_semantics"]
    _write(path, contract)

    report = validate_project(project)

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_ACTION_SEMANTICS_MISSING"
    )
    assert diagnostic.path == "source-contracts/orders.approve.yaml"
    assert diagnostic.pointer == "/action_semantics"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("method", "PUT"),
        ("effect", "update"),
        ("risk", "medium"),
        ("reversibility", "compensatable"),
        ("retry", {"mode": "never"}),
        (
            "idempotency",
            {
                "mode": "source_key",
                "target": {"kind": "header", "name": "X-Idempotency-Key"},
            },
        ),
        ("concurrency", {"mode": "not_supported"}),
    ],
)
def test_validate_project_v2_binds_each_action_semantics_field_to_the_operation(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)
    path = project / "source-contracts" / "orders.approve.yaml"
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    contract["action_semantics"][field] = replacement
    _write(path, contract)

    report = validate_project(project)

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_ACTION_SEMANTICS_MISMATCH"
    )
    assert diagnostic.path == "source-contracts/orders.approve.yaml"
    assert diagnostic.pointer == f"/action_semantics/{field}"


def test_validate_project_v2_rejects_action_semantics_from_unbound_evidence(
    tmp_path: Path,
) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)
    path = project / "source-contracts" / "orders.approve.yaml"
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    contract["action_semantics"]["evidence"] = {
        **_evidence(),
        "digest": "sha256:" + "b" * 64,
    }
    _write(path, contract)

    report = validate_project(project)

    diagnostic = next(
        item for item in report.diagnostics if item.code == "ACC_ACTION_SEMANTICS_EVIDENCE_MISMATCH"
    )
    assert diagnostic.path == "source-contracts/orders.approve.yaml"
    assert diagnostic.pointer == "/action_semantics/evidence"


def test_compile_project_emits_ir_v2_with_quality_enforcement_metadata(tmp_path: Path) -> None:
    report = compile_project(_v2_project(tmp_path))

    assert report.ok, report.diagnostics
    assert report.ir is not None
    assert report.ir["ir_version"] == "2"
    capabilities = cast(dict[str, Any], report.ir["capabilities"])
    capability = cast(dict[str, Any], capabilities["orders.inspect"])
    assert capability["quality"]["max_output_bytes"] == 65536
    assert capability["scope_requirements"] == {
        "policy_always_required": ["orders.read"],
        "always_required": ["orders.read"],
        "conditionally_required": [],
        "all_referenced": ["orders.read"],
        "completion_alternatives": [["orders.read"]],
    }


def test_compile_project_emits_a_proven_action_inventory(tmp_path: Path) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)

    report = compile_project(project)

    assert report.ok, report.diagnostics
    assert report.ir is not None
    capabilities = cast(dict[str, Any], report.ir["capabilities"])
    action = cast(dict[str, Any], capabilities["orders.approve"])
    proof = cast(dict[str, Any], action["action_proof"])
    semantics = cast(dict[str, Any], proof.pop("operation_semantics"))["orders.approve"]
    assert proof == {
        "approval_required": True,
        "effects": ["transition"],
        "maximum_risk": "high",
        "mutation_operation_ids": ["orders.approve"],
        "required_scopes": ["orders.approve", "orders.read"],
    }
    assert semantics["summary"]["method"] == "POST"
    assert semantics["summary"]["effect"] == "transition"
    assert semantics["summary"]["authority"] == "contract"
    assert semantics["digest"].startswith("sha256:")


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda document: document["preview_workflow"].insert(
                1,
                {
                    "id": "current",
                    "pick": {"value": "$.steps.current", "fields": ["id"]},
                },
            ),
            "ACC_COMPILE_STEP_ID_DUPLICATE",
        ),
        (
            lambda document: document["commit_workflow"][0]["call"]["arguments"].update(
                {"order_id": "$.input.order_id"}
            ),
            "ACC_COMPILE_INPUT_REFERENCE_UNAVAILABLE",
        ),
        (
            lambda document: document["preview_workflow"][0]["call"]["arguments"].update(
                {"order_id": "$.prepared.input.order_id"}
            ),
            "ACC_COMPILE_PREPARED_REFERENCE_UNAVAILABLE",
        ),
    ],
)
def test_compile_project_validates_action_workflow_reference_phases(
    tmp_path: Path,
    mutate: Any,
    expected_code: str,
) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)
    path = project / "capabilities" / "orders.approve.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(document)
    _write(path, document)

    report = compile_project(project)

    assert expected_code in {item.code for item in report.diagnostics}


def test_validate_project_v2_enforces_unacknowledged_long_text_disclosure(
    tmp_path: Path,
) -> None:
    project = _v2_project(tmp_path)
    path = project / "capability-quality" / "orders.inspect.yaml"
    quality = yaml.safe_load(path.read_text(encoding="utf-8"))
    quality["output_budget"]["long_text_disclosures"] = [
        {"path": "/description", "acknowledged": False}
    ]
    _write(path, quality)

    report = validate_project(project)

    assert "ACC_CAPABILITY_LONG_TEXT_DISCLOSURE_UNACKNOWLEDGED" in {
        item.code for item in report.diagnostics
    }


def test_v2_project_builds_and_loads_a_versioned_pack(tmp_path: Path) -> None:
    project = _v2_project(tmp_path)
    compiled = compile_project(project)
    assert compiled.ok and compiled.ir is not None
    output = tmp_path / "orders.accpkg"

    built = build_pack(project, output, compiled_ir=compiled.ir)
    verified = verify_pack(output)
    loaded = load_pack(output)

    assert built.manifest.format_version == 2
    assert verified.manifest.format_version == 2
    assert loaded.ir["ir_version"] == "2"
    assert {record.path for record in verified.files} >= {
        "source-contracts/orders.get.yaml",
        "capability-quality/orders.inspect.yaml",
    }


def test_v2_pack_rejects_cross_version_compiled_ir(tmp_path: Path) -> None:
    project = _v2_project(tmp_path)
    compiled = compile_project(project)
    assert compiled.ok and compiled.ir is not None
    mismatched = {**compiled.ir, "ir_version": "1"}

    with pytest.raises(PackFormatError, match="version"):
        build_pack(project, tmp_path / "mismatched.accpkg", compiled_ir=mismatched)


def test_v2_coverage_requires_the_typed_scope_inventory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _v2_project(tmp_path)

    exit_code = cli_main(["coverage", str(project), "--json"])
    payload = yaml.safe_load(capsys.readouterr().out)

    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ACC_COVERAGE_SCOPE_INVENTORY_INVALID"


def test_coverage_rejects_removed_version_selector_without_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _v2_project(tmp_path)
    _add_action(project)

    exit_code = cli_main(["coverage", str(project), "--version", "1", "--json"])
    captured = capsys.readouterr()
    payload = yaml.safe_load(captured.out)

    assert exit_code == 2
    assert captured.err == ""
    assert payload == {
        "ok": False,
        "command": "coverage",
        "result": None,
        "diagnostics": [
            {
                "code": "ACC_CLI_USAGE",
                "severity": "error",
                "message": "unrecognized arguments: --version 1",
                "path": None,
                "pointer": None,
            }
        ],
    }
