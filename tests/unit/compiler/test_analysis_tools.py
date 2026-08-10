from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from acc_core.compiler import CompilationReport
from acc_core.compiler.diff import semantic_diff
from acc_core.contracts import SourceContract
from acc_core.coverage import (
    LiveObservation,
    analyze_coverage,
    analyze_coverage_v1,
    analyze_coverage_v2,
)
from acc_core.evidence import EvidenceFreezeError, freeze_operation_evidence
from acc_core.io import InvalidProjectPathError, ProjectFileTooLargeError, ProjectSymlinkError
from acc_core.models import Capability, Eval, Operation, Policy
from acc_core.packaging import PackManifest
from acc_core.quality import CapabilityQuality
from acc_core.scope import ScopeInventory
from acc_core.validation import ValidationReport


def _operation(identifier: str) -> Operation:
    return Operation.model_validate(
        {
            "schema_version": "1",
            "id": identifier,
            "title": identifier,
            "kind": "http",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "http": {
                "method": "GET",
                "path": "/customers",
                "credential_ref": "CRM_TOKEN",
                "scopes": ["customer.read"],
            },
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": "crm",
                    "locator": "api/customers.py#L1-L10",
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        }
    )


def _capability(identifier: str, operation: str, eval_ids: list[str]) -> Capability:
    return Capability.model_validate(
        {
            "schema_version": "1",
            "id": identifier,
            "title": identifier,
            "description": identifier,
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "workflow": [
                {"call": {"operation": operation, "arguments": {}}},
                {"emit": {"value": "$.steps.call"}},
            ],
            "policy": "customer-read",
            "evals": eval_ids,
        }
    )


def _policy() -> Policy:
    return Policy.model_validate(
        {
            "schema_version": "1",
            "id": "customer-read",
            "required_scopes": ["customer.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["id"],
            "denied_fields": [],
            "redaction_rules": [],
        }
    )


def _eval(identifier: str, capability: str, *, error_status: int | None = None) -> Eval:
    document: dict[str, object] = {
        "schema_version": "1",
        "id": identifier,
        "capability": capability,
        "input": {},
        "fixtures": {},
        "expected_calls": [],
        "forbidden_fields": [],
    }
    if error_status is None:
        document["expected_output_schema"] = {"type": "object"}
    else:
        document["expected_error"] = {
            "code": "ACC_PROVIDER_FORBIDDEN",
            "status": error_status,
        }
    return Eval.model_validate(document)


def test_coverage_reports_stable_analysis_findings() -> None:
    report = ValidationReport(
        operations={
            "crm.get_customer": _operation("crm.get_customer"),
            "crm.orphan": _operation("crm.orphan"),
        },
        capabilities={
            "get_customer": _capability(
                "get_customer", "crm.get_customer", ["get-customer-positive"]
            ),
            "missing_eval": _capability("missing_eval", "crm.get_customer", ["not-created"]),
        },
        policies={"customer-read": _policy()},
        evals={
            "get-customer-positive": _eval("get-customer-positive", "get_customer"),
            "unlinked-negative": _eval("unlinked-negative", "get_customer", error_status=403),
        },
    )

    result = analyze_coverage(report)

    assert result == {
        "coverage_version": "1",
        "summary": {
            "operations": 2,
            "capabilities": 2,
            "evals": 2,
            "findings": 8,
        },
        "orphan_operations": ["crm.orphan"],
        "capabilities_without_evals": ["missing_eval"],
        "capabilities_without_negative_evals": ["get_customer", "missing_eval"],
        "capabilities_without_permission_negative_evals": ["get_customer", "missing_eval"],
        "one_interface_one_tool_risks": ["get_customer", "missing_eval"],
    }
    assert json.dumps(result, sort_keys=True, separators=(",", ":")) == json.dumps(
        analyze_coverage(report), sort_keys=True, separators=(",", ":")
    )


def test_coverage_recognizes_a_linked_permission_negative_eval() -> None:
    report = ValidationReport(
        operations={"crm.get_customer": _operation("crm.get_customer")},
        capabilities={
            "get_customer": _capability(
                "get_customer",
                "crm.get_customer",
                ["get-customer-positive", "get-customer-forbidden"],
            )
        },
        policies={"customer-read": _policy()},
        evals={
            "get-customer-positive": _eval("get-customer-positive", "get_customer"),
            "get-customer-forbidden": _eval(
                "get-customer-forbidden", "get_customer", error_status=403
            ),
        },
    )

    result = analyze_coverage(report)

    assert result["capabilities_without_negative_evals"] == []
    assert result["capabilities_without_permission_negative_evals"] == []


def _scope_inventory(
    *,
    operation_id: str = "crm.get_customer",
    method: str = "GET",
    path: str = "/customers",
) -> ScopeInventory:
    return ScopeInventory.model_validate(
        {
            "schema_version": "1",
            "scope": {
                "mode": "domain_complete",
                "selected_domains": ["crm"],
                "exclusion_approval": {},
            },
            "discovery": None,
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": [
                {
                    "id": f"{method} {path}",
                    "domain": "crm",
                    "method": method,
                    "path": path,
                    "evidence_sources": ["routes.py"],
                    "eligibility": "eligible",
                    "disposition": "composed",
                    "operation_id": operation_id,
                    "capability_ids": ["get_customer"],
                },
                {
                    "id": "GET /internal/export",
                    "domain": "crm",
                    "method": "GET",
                    "path": "/internal/export",
                    "evidence_sources": ["routes.py"],
                    "eligibility": "ineligible",
                    "disposition": "excluded",
                    "reason": "Binary export is outside the JSON capability boundary.",
                },
            ],
            "summary": {
                "discovered_routes": 2,
                "eligible_read_routes": 1,
                "planned": 0,
                "composed": 1,
                "excluded": 1,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        }
    )


def _capability_quality() -> CapabilityQuality:
    return CapabilityQuality.model_validate(
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "intent": {"action": "get", "resource_types": ["customer"]},
            "inputs": {},
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65_536, "long_text_disclosures": []},
        }
    )


def _source_contract(operation: Operation) -> SourceContract:
    return SourceContract.model_validate(
        {
            "schema_version": "2",
            "id": "crm.get_customer.contract",
            "operation_id": operation.id,
            "request_schema": operation.input_schema,
            "response_schema": operation.output_schema,
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
        }
    )


def test_coverage_v1_named_api_preserves_the_exact_legacy_document() -> None:
    report = ValidationReport(
        operations={"crm.get_customer": _operation("crm.get_customer")},
        capabilities={
            "get_customer": _capability(
                "get_customer", "crm.get_customer", ["get-customer-positive"]
            )
        },
        policies={"customer-read": _policy()},
        evals={"get-customer-positive": _eval("get-customer-positive", "get_customer")},
    )

    assert analyze_coverage_v1(report) == analyze_coverage(report)


def test_coverage_v2_reports_independent_axes_without_a_total_score() -> None:
    operation = _operation("crm.get_customer")
    report = ValidationReport(
        operations={operation.id: operation},
        capabilities={
            "get_customer": _capability("get_customer", operation.id, ["get-customer-positive"])
        },
        source_contracts={operation.id: _source_contract(operation)},
        capability_quality={"get_customer": _capability_quality()},
        policies={"customer-read": _policy()},
        evals={"get-customer-positive": _eval("get-customer-positive", "get_customer")},
    )

    result = analyze_coverage_v2(report, _scope_inventory())
    document = result.model_dump(mode="json")

    assert list(document) == [
        "coverage_version",
        "route_disposition",
        "operation_trace",
        "scenario_coverage",
        "constructability",
        "discoverability_graph",
        "composition",
        "schema_fidelity",
        "output_budget",
        "live_observations",
    ]
    assert "score" not in json.dumps(document)
    assert result.route_disposition.composed == ["GET /customers"]
    assert result.route_disposition.excluded == ["GET /internal/export"]
    assert result.operation_trace.traced_route_ids == ["GET /customers"]
    assert result.operation_trace.broken_route_ids == []
    assert result.scenario_coverage.with_success == ["get_customer"]
    assert result.scenario_coverage.without_negative == ["get_customer"]
    assert result.constructability.reachable == ["get_customer"]
    assert result.discoverability_graph.nodes == ["get_customer"]
    assert result.composition.components == {"get_customer": 1}
    assert result.composition.diagnostics == []
    assert result.schema_fidelity.analyzed_operation_ids == ["crm.get_customer"]
    assert result.schema_fidelity.diagnostics == []
    assert result.output_budget.status_by_capability == {"get_customer": "unknown"}
    assert result.live_observations.status == "not_observed"
    assert result.live_observations.unobserved_capability_ids == ["get_customer"]


def test_coverage_v2_does_not_treat_route_disposition_as_usable() -> None:
    operation = _operation("crm.get_customer")
    report = ValidationReport(
        operations={operation.id: operation},
        capabilities={
            "get_customer": _capability("get_customer", operation.id, ["get-customer-positive"])
        },
        capability_quality={"get_customer": _capability_quality()},
        policies={"customer-read": _policy()},
        evals={"get-customer-positive": _eval("get-customer-positive", "get_customer")},
    )

    result = analyze_coverage_v2(
        report,
        _scope_inventory(operation_id="crm.operation_not_compiled"),
    )

    assert result.route_disposition.composed == ["GET /customers"]
    assert result.operation_trace.broken_route_ids == ["GET /customers"]
    assert "usable" not in result.route_disposition.model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("HEAD", "/customers"),
        ("GET", "/customers/{customer_id}"),
    ],
)
def test_coverage_v2_marks_route_broken_when_http_mapping_is_not_exact(
    method: str,
    path: str,
) -> None:
    operation = _operation("crm.get_customer")
    report = ValidationReport(
        operations={operation.id: operation},
        capabilities={
            "get_customer": _capability("get_customer", operation.id, ["get-customer-positive"])
        },
        capability_quality={"get_customer": _capability_quality()},
        policies={"customer-read": _policy()},
        evals={"get-customer-positive": _eval("get-customer-positive", "get_customer")},
    )

    result = analyze_coverage_v2(
        report,
        _scope_inventory(method=method, path=path),
    )

    route_id = f"{method} {path}"
    assert result.operation_trace.traced_route_ids == []
    assert result.operation_trace.broken_route_ids == [route_id]


def test_coverage_v2_keeps_live_observations_separate_from_static_output_bounds() -> None:
    operation = _operation("crm.get_customer")
    report = ValidationReport(
        operations={operation.id: operation},
        capabilities={
            "get_customer": _capability("get_customer", operation.id, ["get-customer-positive"])
        },
        capability_quality={"get_customer": _capability_quality()},
        policies={"customer-read": _policy()},
        evals={"get-customer-positive": _eval("get-customer-positive", "get_customer")},
    )
    observation = LiveObservation(
        capability_id="get_customer",
        verification_level="source_connected_verified",
        sample_count=20,
        response_bytes_p50=1_024,
        response_bytes_p95=4_096,
        response_bytes_max=8_192,
    )

    result = analyze_coverage_v2(report, _scope_inventory(), live_observations=[observation])

    assert result.output_budget.status_by_capability == {"get_customer": "unknown"}
    assert result.live_observations.status == "observed"
    assert result.live_observations.observations == [observation]
    assert result.live_observations.unobserved_capability_ids == []


def test_semantic_diff_ignores_mapping_order_and_reports_recursive_changes() -> None:
    before = {
        "ir_version": "1",
        "operations": {
            "crm.get": {"method": "GET", "scopes": ["read"]},
            "crm.old": {"method": "GET"},
        },
        "project": {"version": "0.1.0", "id": "crm"},
    }
    after = {
        "project": {"id": "crm", "version": "0.2.0"},
        "operations": {
            "crm.new": {"method": "GET"},
            "crm.get": {"scopes": ["read", "admin"], "method": "GET"},
        },
        "ir_version": "1",
    }

    result = semantic_diff(before, after)

    assert result == {
        "diff_version": "1",
        "has_changes": True,
        "added": [
            {"path": "/operations/crm.new", "value": {"method": "GET"}},
            {"path": "/operations/crm.get/scopes/1", "value": "admin"},
        ],
        "removed": [
            {"path": "/operations/crm.old", "value": {"method": "GET"}},
        ],
        "modified": [{"path": "/project/version", "before": "0.1.0", "after": "0.2.0"}],
    }
    assert semantic_diff({"b": 2, "a": 1}, {"a": 1, "b": 2})["has_changes"] is False


def test_semantic_diff_accepts_compilation_reports_and_pack_manifests() -> None:
    before_ir = CompilationReport(ir={"ir_version": "1", "operations": {}})
    after_ir = CompilationReport(ir={"operations": {}, "ir_version": "1"})
    before_manifest = PackManifest("acc.capability-pack", 1, "crm", "0.1.0")
    after_manifest = PackManifest("acc.capability-pack", 1, "crm", "0.2.0")

    assert semantic_diff(before_ir, after_ir)["has_changes"] is False
    assert semantic_diff(before_manifest, after_manifest)["modified"] == [
        {"path": "/project/version", "before": "0.1.0", "after": "0.2.0"}
    ]


def test_semantic_diff_rejects_non_finite_numbers() -> None:
    with pytest.raises(TypeError, match="finite"):
        semantic_diff({"value": float("nan")}, {"value": 1.0})


def _write_freeze_project(root: Path, locator: str = "api/customers.py#L1-L2") -> Path:
    source = root / "source"
    source.mkdir()
    (source / "api").mkdir()
    (source / "api" / "customers.py").write_bytes(b"def get_customer():\n    return {}\n")

    project = root / "acc-project"
    (project / "operations").mkdir(parents=True)
    (project / "project.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "project": {"id": "crm", "version": "0.1.0"},
                "source_workspace": {"path": "../source", "mode": "read_only"},
                "runtime": {"transport": ["stdio"]},
                "provider": {"kind": "http", "base_url_ref": "CRM_URL"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    operation = _operation("crm.get_customer").model_dump(mode="json", by_alias=True)
    operation["evidence"][0]["locator"] = locator
    (project / "operations" / "get-customer.yaml").write_text(
        yaml.safe_dump(operation, sort_keys=False), encoding="utf-8"
    )
    return project


def test_freeze_previews_digest_and_only_writes_the_acc_operation(tmp_path: Path) -> None:
    project = _write_freeze_project(tmp_path)
    source_file = tmp_path / "source" / "api" / "customers.py"
    operation_file = project / "operations" / "get-customer.yaml"
    source_before = source_file.read_bytes()
    operation_before = operation_file.read_bytes()
    expected_digest = f"sha256:{hashlib.sha256(source_before).hexdigest()}"

    preview = freeze_operation_evidence(project, "crm.get_customer")

    assert preview == {
        "freeze_version": "1",
        "operation_id": "crm.get_customer",
        "operation_path": "operations/get-customer.yaml",
        "written": False,
        "evidence": [
            {
                "index": 0,
                "path": "api/customers.py",
                "size_bytes": len(source_before),
                "digest": expected_digest,
            }
        ],
    }
    assert operation_file.read_bytes() == operation_before
    assert source_file.read_bytes() == source_before

    written = freeze_operation_evidence(project, "crm.get_customer", write=True)

    assert written["written"] is True
    frozen = yaml.safe_load(operation_file.read_text(encoding="utf-8"))
    assert frozen["evidence"][0]["digest"] == expected_digest
    assert source_file.read_bytes() == source_before


def test_freeze_rejects_locator_traversal_without_writing(tmp_path: Path) -> None:
    project = _write_freeze_project(tmp_path, "../outside.py#L1")
    operation_file = project / "operations" / "get-customer.yaml"
    before = operation_file.read_bytes()

    with pytest.raises(InvalidProjectPathError):
        freeze_operation_evidence(project, "crm.get_customer", write=True)

    assert operation_file.read_bytes() == before


def test_freeze_rejects_source_symlinks_without_writing(tmp_path: Path) -> None:
    project = _write_freeze_project(tmp_path, "api/linked.py#L1")
    source_file = tmp_path / "source" / "api" / "customers.py"
    (tmp_path / "source" / "api" / "linked.py").symlink_to(source_file)
    operation_file = project / "operations" / "get-customer.yaml"
    before = operation_file.read_bytes()

    with pytest.raises(ProjectSymlinkError):
        freeze_operation_evidence(project, "crm.get_customer", write=True)

    assert operation_file.read_bytes() == before


def test_freeze_enforces_source_file_size_limit(tmp_path: Path) -> None:
    project = _write_freeze_project(tmp_path)

    with pytest.raises(ProjectFileTooLargeError):
        freeze_operation_evidence(project, "crm.get_customer", max_bytes=8)


def test_freeze_rejects_a_source_workspace_containing_the_acc_project(
    tmp_path: Path,
) -> None:
    project = _write_freeze_project(tmp_path)
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "customers.py").write_bytes(b"source system\n")
    project_document = yaml.safe_load((project / "project.yaml").read_text(encoding="utf-8"))
    project_document["source_workspace"]["path"] = ".."
    (project / "project.yaml").write_text(
        yaml.safe_dump(project_document, sort_keys=False), encoding="utf-8"
    )
    operation_file = project / "operations" / "get-customer.yaml"
    before = operation_file.read_bytes()

    with pytest.raises(EvidenceFreezeError, match="contains the ACC project"):
        freeze_operation_evidence(project, "crm.get_customer", write=True)

    assert operation_file.read_bytes() == before


def test_freeze_rejects_a_source_workspace_inside_the_acc_project(tmp_path: Path) -> None:
    project = _write_freeze_project(tmp_path)
    nested_source = project / "source" / "api"
    nested_source.mkdir(parents=True)
    (nested_source / "customers.py").write_bytes(b"nested source system\n")
    project_document = yaml.safe_load((project / "project.yaml").read_text(encoding="utf-8"))
    project_document["source_workspace"]["path"] = "source"
    (project / "project.yaml").write_text(
        yaml.safe_dump(project_document, sort_keys=False), encoding="utf-8"
    )
    operation_file = project / "operations" / "get-customer.yaml"
    before = operation_file.read_bytes()

    with pytest.raises(EvidenceFreezeError, match="overlap"):
        freeze_operation_evidence(project, "crm.get_customer", write=True)

    assert operation_file.read_bytes() == before
