from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "interaction_audit.py"
TEMPLATES = ROOT / "skills" / "acc-engineer" / "templates"


def _evidence(source_id: str = "customer-page") -> dict[str, object]:
    return {
        "source_id": source_id,
        "kind": "source_file",
        "path": "frontend/customers.ts",
        "line_start": 1,
        "line_end": 40,
        "digest": "sha256:" + "a" * 64,
    }


def _scope_inventory(*, interaction_ids: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": "2",
        "scope": {"mode": "system_complete"},
        "routes": [
            {
                "id": "customer.search",
                "usage_evidence_sources": ["customer-page"],
                "interaction_ids": (
                    ["customers.initial-load"] if interaction_ids is None else interaction_ids
                ),
            }
        ],
    }


def _ui_inventory() -> dict[str, object]:
    return {
        "schema_version": "2",
        "scope": {"mode": "complete", "evidence_sources": ["frontend-tree"]},
        "surfaces": [
            {
                "id": "customers",
                "kind": "page",
                "route_or_entry": "/customers",
                "usage_context": "customers-list-page",
                "business_purpose": "Manage customers",
                "evidence_sources": ["customer-page"],
                "entry_evidence": _evidence(),
            }
        ],
        "interactions": [
            {
                "id": "customers.initial-load",
                "surface_id": "customers",
                "business_intent": "Load visible customers",
                "trigger": {"kind": "screen_load"},
                "route_ids": ["customer.search"],
                "call_order": "sequential",
                "input_bindings": [],
                "defaults": [],
                "option_sources": [],
                "conditions": [],
                "related_data": [],
                "result_consumption": [],
                "states": [],
                "dimension_dispositions": [
                    {
                        "dimension": dimension,
                        "applicability": "not_applicable",
                        "rationale": f"The initial load has no {dimension} behavior.",
                        "evidence": _evidence(),
                    }
                    for dimension in (
                        "conditions",
                        "defaults",
                        "input_bindings",
                        "option_sources",
                        "related_data",
                        "result_consumption",
                        "states",
                    )
                ],
                "evidence_claims": [
                    {
                        "target_pointer": "/interactions/0",
                        "evidence": _evidence(),
                        "evidence_pointer": "/route_ids/0",
                        "authority": "implementation",
                    }
                ],
                "unknowns": [],
            }
        ],
        "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
    }


def _contract(*, interaction_ids: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": "2",
        "capability_id": "search_customers",
        "interaction_ids": (
            ["customers.initial-load"] if interaction_ids is None else interaction_ids
        ),
        "public_input_bindings": [],
        "trusted_input_bindings": [],
        "defaults": [],
        "option_sources": [],
        "conditions": [],
        "related_data": [],
        "result_consumption": [],
        "required_scenarios": ["search_customers_initial_load"],
        "omissions": [],
    }


def _write_project(
    tmp_path: Path,
    *,
    scope: dict[str, object] | None = None,
    inventory: dict[str, object] | None = None,
    contract: dict[str, object] | None = None,
    write_contract: bool = True,
) -> Path:
    project = tmp_path / "acc-project"
    project.mkdir()
    (project / "interaction-contracts").mkdir()
    (project / "scope-inventory.yaml").write_text(
        yaml.safe_dump(scope or _scope_inventory(), sort_keys=False), encoding="utf-8"
    )
    (project / "ui-interaction-inventory.yaml").write_text(
        yaml.safe_dump(inventory or _ui_inventory(), sort_keys=False), encoding="utf-8"
    )
    if write_contract:
        (project / "interaction-contracts" / "search_customers.yaml").write_text(
            yaml.safe_dump(contract or _contract(), sort_keys=False), encoding="utf-8"
        )
    return project


def _run(project: Path, *, output: bool = False) -> tuple[subprocess.CompletedProcess[str], Any]:
    arguments = [sys.executable, str(SCRIPT), "--project", str(project)]
    if output:
        arguments.extend(["--output", "interaction-audit-report.json"])
    completed = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, check=False)
    return completed, json.loads(completed.stdout)


def _codes(payload: dict[str, object]) -> set[str]:
    diagnostics = payload["diagnostics"]
    assert isinstance(diagnostics, list)
    return {str(item["code"]) for item in diagnostics}


def test_interaction_audit_accepts_closed_normalized_documents_and_writes_report(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path)

    completed, payload = _run(project, output=True)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"] == {
        "contracts": 1,
        "interactions": 1,
        "scope_mode": "complete",
        "surfaces": 1,
        "unresolved": 0,
    }
    assert json.loads((project / "interaction-audit-report.json").read_text()) == payload


def test_complete_interaction_rejects_empty_dimensions_without_dispositions(
    tmp_path: Path,
) -> None:
    inventory = _ui_inventory()
    inventory["interactions"][0]["dimension_dispositions"] = []  # type: ignore[index]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_DIMENSION_DISPOSITION_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_complete_interaction_rejects_orphan_dimension_evidence(tmp_path: Path) -> None:
    inventory = _ui_inventory()
    dispositions = inventory["interactions"][0]["dimension_dispositions"]  # type: ignore[index]
    dispositions[0]["evidence"]["source_id"] = "orphan-source"
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_DIMENSION_EVIDENCE_UNRESOLVED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_complete_interaction_rejects_duplicate_surface_usage_context(
    tmp_path: Path,
) -> None:
    inventory = _ui_inventory()
    duplicate = dict(inventory["surfaces"][0])  # type: ignore[index]
    duplicate["id"] = "customers-mobile"
    cast(list[object], inventory["surfaces"]).append(duplicate)
    inventory["summary"]["surfaces"] = 2  # type: ignore[index]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_SURFACE_CONTEXT_DUPLICATE" in {item["code"] for item in payload["diagnostics"]}


def test_system_complete_frontend_denominator_rejects_discovered_ui_scope(
    tmp_path: Path,
) -> None:
    inventory = _ui_inventory()
    inventory["scope"]["mode"] = "discovered"  # type: ignore[index]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_SYSTEM_SCOPE_INCOMPLETE" in {item["code"] for item in payload["diagnostics"]}


def test_interaction_audit_rejects_interaction_route_unknown_to_scope(tmp_path: Path) -> None:
    inventory = _ui_inventory()
    inventory["interactions"][0]["route_ids"] = ["customer.missing"]  # type: ignore[index]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_INTERACTION_ROUTE_UNKNOWN" in _codes(payload)


def test_interaction_audit_rejects_scope_interaction_unknown_to_inventory(tmp_path: Path) -> None:
    project = _write_project(tmp_path, scope=_scope_inventory(interaction_ids=["missing"]))

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_INTERACTION_UNKNOWN" in _codes(payload)


def test_interaction_audit_rejects_contract_interaction_unknown_to_inventory(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path, contract=_contract(interaction_ids=["missing"]))

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_INTERACTION_UNKNOWN" in _codes(payload)


def test_interaction_audit_rejects_complete_inventory_with_unresolved_items(tmp_path: Path) -> None:
    inventory = _ui_inventory()
    inventory["interactions"][0]["unknowns"] = ["conditional source is unknown"]  # type: ignore[index]
    inventory["summary"]["unresolved"] = 1  # type: ignore[index]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_SURFACE_COVERAGE_INCOMPLETE" in _codes(payload)


def test_interaction_audit_rejects_missing_surface_and_interaction_evidence(tmp_path: Path) -> None:
    inventory = _ui_inventory()
    inventory["surfaces"][0]["evidence_sources"] = []  # type: ignore[index]
    inventory["interactions"][0]["evidence_claims"] = []  # type: ignore[index]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_INTERACTION_EVIDENCE_MISSING" in _codes(payload)


def test_interaction_audit_rejects_incomplete_evidence_claim_object(tmp_path: Path) -> None:
    secret = "do-not-echo-evidence-path"
    inventory = _ui_inventory()
    inventory["interactions"][0]["evidence_claims"] = [  # type: ignore[index]
        {
            "target_pointer": "/interactions/0",
            "evidence": {"path": secret},
            "authority": "implementation",
        }
    ]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_INTERACTION_EVIDENCE_MISSING" in _codes(payload)
    assert secret not in json.dumps(payload)


def test_interaction_audit_rejects_duplicate_denominator_ids(tmp_path: Path) -> None:
    inventory = _ui_inventory()
    first_surface = inventory["surfaces"][0]  # type: ignore[index]
    inventory["surfaces"] = [first_surface, first_surface]
    first_interaction = inventory["interactions"][0]  # type: ignore[index]
    inventory["interactions"] = [first_interaction, first_interaction]
    inventory["summary"] = {"surfaces": 2, "interactions": 2, "unresolved": 0}
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_DOCUMENT_INVALID" in _codes(payload)


def test_interaction_audit_rejects_duplicate_capability_contract_ids(tmp_path: Path) -> None:
    project = _write_project(tmp_path)
    (project / "interaction-contracts" / "duplicate.yaml").write_text(
        yaml.safe_dump(_contract(), sort_keys=False), encoding="utf-8"
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_DOCUMENT_INVALID" in _codes(payload)


def test_interaction_audit_accepts_evidenced_none_scope_without_contracts(tmp_path: Path) -> None:
    inventory: dict[str, object] = {
        "schema_version": "2",
        "scope": {
            "mode": "none",
            "evidence_sources": ["frontend-discovery"],
            "rationale": "No applicable interactive client surface exists",
        },
        "surfaces": [],
        "interactions": [],
        "summary": {"surfaces": 0, "interactions": 0, "unresolved": 0},
    }
    project = _write_project(
        tmp_path,
        scope=_scope_inventory(interaction_ids=[]),
        inventory=inventory,
        write_contract=False,
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["result"]["contracts"] == 0
    assert payload["result"]["scope_mode"] == "none"


def test_interaction_audit_rejects_unauthorised_none_scope(tmp_path: Path) -> None:
    inventory: dict[str, object] = {
        "schema_version": "2",
        "scope": {"mode": "none", "evidence_sources": [], "rationale": None},
        "surfaces": [],
        "interactions": [],
        "summary": {"surfaces": 0, "interactions": 0, "unresolved": 0},
    }
    project = _write_project(
        tmp_path,
        scope=_scope_inventory(interaction_ids=[]),
        inventory=inventory,
        write_contract=False,
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_DOCUMENT_INVALID" in _codes(payload)


def test_interaction_audit_rejects_non_current_or_malformed_yaml_structure(tmp_path: Path) -> None:
    inventory = _ui_inventory()
    inventory["schema_version"] = "1"
    inventory["surfaces"] = {"id": "not-a-list"}
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_UI_DOCUMENT_INVALID" in _codes(payload)


def test_interaction_audit_diagnostics_never_echo_secret_values_or_evidence_paths(
    tmp_path: Path,
) -> None:
    secret = "do-not-echo-password-or-path"
    inventory = _ui_inventory()
    inventory["interactions"][0]["route_ids"] = [secret]  # type: ignore[index]
    inventory["interactions"][0]["evidence_claims"] = [  # type: ignore[index]
        {
            "target_pointer": "/interactions/0",
            "evidence": _evidence(secret),
            "evidence_pointer": "/route_ids/0",
            "authority": "implementation",
        }
    ]
    project = _write_project(tmp_path, inventory=inventory)

    completed, payload = _run(project)

    assert completed.returncode == 3
    serialized = json.dumps(payload, ensure_ascii=False)
    assert secret not in serialized
    assert str(project) not in serialized


def test_interaction_templates_are_current_safe_and_do_not_fabricate_usage() -> None:
    scope = yaml.safe_load((TEMPLATES / "scope-inventory.yaml").read_text(encoding="utf-8"))
    inventory = yaml.safe_load(
        (TEMPLATES / "ui-interaction-inventory.yaml").read_text(encoding="utf-8")
    )
    contract = yaml.safe_load((TEMPLATES / "interaction-contract.yaml").read_text(encoding="utf-8"))

    assert scope["routes"][0]["usage_evidence_sources"] == []
    assert scope["routes"][0]["interaction_ids"] == []
    assert inventory["schema_version"] == "2"
    assert inventory["scope"]["mode"] == "discovered"
    claim = inventory["interactions"][0]["evidence_claims"][0]
    assert "evidence_source" not in claim
    assert set(claim) == {"target_pointer", "evidence", "evidence_pointer", "authority"}
    assert {"source_id", "path", "digest"} <= set(claim["evidence"])
    assert contract["schema_version"] == "2"
    assert contract["interaction_ids"]
