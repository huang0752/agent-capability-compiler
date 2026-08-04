from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from acc_core.compiler import CompilationReport
from acc_core.compiler.diff import semantic_diff
from acc_core.coverage import analyze_coverage
from acc_core.evidence import EvidenceFreezeError, freeze_operation_evidence
from acc_core.io import InvalidProjectPathError, ProjectFileTooLargeError, ProjectSymlinkError
from acc_core.models import Capability, Eval, Operation, Policy
from acc_core.packaging import PackManifest
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
