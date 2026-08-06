from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ACC_CORE_SRC = REPOSITORY_ROOT / "packages" / "acc-core" / "src"
JSON_SCHEMA_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
EXPORTED_SCHEMAS = {
    "capability.schema.json",
    "eval.schema.json",
    "evidence.schema.json",
    "operation.schema.json",
    "policy.schema.json",
    "project.schema.json",
}
PROJECT_DIRECTORIES = {"capabilities", "evals", "evidence", "operations", "policies"}


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path = REPOSITORY_ROOT,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    current_pythonpath = env.get("PYTHONPATH")
    pythonpath_entries = [str(ACC_CORE_SRC)]
    if current_pythonpath:
        pythonpath_entries.append(current_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )


def _run_acc(*arguments: str, cwd: Path = REPOSITORY_ROOT) -> subprocess.CompletedProcess[str]:
    return _run_command(
        [sys.executable, "-m", "acc_core.cli.main", *arguments],
        cwd=cwd,
    )


def _json_envelope(
    completed: subprocess.CompletedProcess[str],
    *,
    command: str,
    ok: bool,
    allow_warnings: bool = False,
) -> dict[str, Any]:
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        pytest.fail(
            "CLI --json output is not one JSON document:\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )

    assert set(payload) == {"ok", "command", "result", "diagnostics"}
    assert payload["ok"] is ok
    assert payload["command"] == command
    assert isinstance(payload["diagnostics"], list)
    if ok:
        assert isinstance(payload["result"], dict)
        if allow_warnings:
            assert all(item["severity"] != "error" for item in payload["diagnostics"])
        else:
            assert payload["diagnostics"] == []
    else:
        assert payload["result"] is None
        assert payload["diagnostics"]
    return cast(dict[str, Any], payload)


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _make_valid_project(root: Path) -> Path:
    project = root / "acc-project"
    (root / "system").mkdir()
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "1",
            "project": {"id": "example-crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
        },
    )
    _write_yaml(
        project / "operations" / "crm.get_customer.yaml",
        {
            "schema_version": "1",
            "id": "crm.get_customer",
            "title": "Get customer",
            "kind": "http",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
            },
            "output_schema": {"type": "object"},
            "http": {
                "method": "GET",
                "path": "/customers/{customer_id}",
                "path_parameters": {"customer_id": "customer_id"},
                "credential_ref": "CRM_USER_TOKEN",
                "scopes": ["customer.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 1_048_576,
            },
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": "crm-backend",
                    "locator": "app/api/customers.py#L42-L68",
                    "digest": f"sha256:{'a' * 64}",
                }
            ],
        },
    )
    _write_yaml(
        project / "policies" / "crm-sales-read.yaml",
        {
            "schema_version": "1",
            "id": "crm-sales-read",
            "required_scopes": ["customer.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["id", "name", "tenant_id"],
            "denied_fields": ["internal_note"],
            "redaction_rules": [],
        },
    )
    _write_yaml(
        project / "capabilities" / "get_customer.yaml",
        {
            "schema_version": "1",
            "id": "get_customer",
            "title": "Get customer context",
            "description": "Get one customer's context.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["customer_id"],
                "properties": {"customer_id": {"type": "string"}},
            },
            "output_schema": {"type": "object"},
            "workflow": [
                {
                    "id": "customer",
                    "call": {
                        "operation": "crm.get_customer",
                        "arguments": {"customer_id": "$.input.customer_id"},
                    },
                },
                {"emit": {"value": "$.steps.customer"}},
            ],
            "policy": "crm-sales-read",
            "evals": ["get-customer-normal"],
        },
    )
    _write_yaml(
        project / "evals" / "get-customer-normal.yaml",
        {
            "schema_version": "1",
            "id": "get-customer-normal",
            "capability": "get_customer",
            "input": {"customer_id": "c-1"},
            "fixtures": {},
            "expected_calls": [
                {"operation": "crm.get_customer", "arguments": {"customer_id": "c-1"}}
            ],
            "expected_output_schema": {"type": "object"},
            "forbidden_fields": ["internal_note"],
        },
    )
    return project


def test_acc_console_entrypoint_help_lists_milestone_one_commands() -> None:
    completed = _run_command(["uv", "run", "--frozen", "acc", "--help"])

    assert completed.returncode == 0, completed.stderr
    help_text = completed.stdout.lower()
    assert "usage: acc" in help_text
    for command in ("init", "doctor", "schema", "validate"):
        assert command in help_text


def test_init_creates_minimal_project_and_never_overwrites(tmp_path: Path) -> None:
    project = tmp_path / "my-acc-project"

    completed = _run_acc("init", str(project), "--json")

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(completed, command="init", ok=True)
    assert Path(payload["result"]["path"]) == project.resolve()
    assert (project / "project.yaml").is_file()
    assert {entry.name for entry in project.iterdir() if entry.is_dir()} >= PROJECT_DIRECTORIES

    original = (project / "project.yaml").read_text(encoding="utf-8")
    protected_content = f"{original}\n# this existing project must not be overwritten\n"
    (project / "project.yaml").write_text(protected_content, encoding="utf-8")

    repeated = _run_acc("init", str(project), "--json")

    assert repeated.returncode == 3
    repeated_payload = _json_envelope(repeated, command="init", ok=False)
    assert repeated_payload["diagnostics"][0]["code"] == "ACC_PROJECT_EXISTS"
    assert (project / "project.yaml").read_text(encoding="utf-8") == protected_content


def test_doctor_reports_environment_and_project_checks(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("doctor", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="doctor",
        ok=True,
        allow_warnings=True,
    )
    checks = {check["name"]: check for check in payload["result"]["checks"]}
    assert {"python", "project"} <= checks.keys()
    assert checks["python"]["ok"] is True
    assert checks["project"]["ok"] is True
    assert [item["code"] for item in payload["diagnostics"]] == ["ACC_AUTH_LEGACY_CREDENTIAL"]


def test_schema_exports_all_models_as_draft_2020_12(tmp_path: Path) -> None:
    output = tmp_path / "schemas"

    completed = _run_acc("schema", "--output", str(output), "--json")

    assert completed.returncode == 0, completed.stderr
    _json_envelope(completed, command="schema", ok=True)
    assert {entry.name for entry in output.iterdir()} == EXPORTED_SCHEMAS
    for schema_path in output.iterdir():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["$schema"] == JSON_SCHEMA_DRAFT_2020_12

    project_schema = json.loads((output / "project.schema.json").read_text(encoding="utf-8"))

    def discriminators(value: object) -> list[dict[str, object]]:
        if isinstance(value, dict):
            found = [value["discriminator"]] if "discriminator" in value else []
            return found + [item for child in value.values() for item in discriminators(child)]
        if isinstance(value, list):
            return [item for child in value for item in discriminators(child)]
        return []

    kind_discriminators = [
        item for item in discriminators(project_schema) if item["propertyName"] == "kind"
    ]
    assert len(kind_discriminators) >= 2


def test_validate_accepts_an_evidence_bound_project(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("validate", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="validate",
        ok=True,
        allow_warnings=True,
    )
    assert payload["result"]["project_id"] == "example-crm"
    assert payload["result"]["counts"] == {
        "operations": 1,
        "capabilities": 1,
        "policies": 1,
        "evals": 1,
    }
    assert payload["diagnostics"] == [
        {
            "code": "ACC_AUTH_LEGACY_CREDENTIAL",
            "severity": "warning",
            "message": (
                "Legacy Operation-level credentials remain supported for stdio; "
                "migrate authentication to provider.auth."
            ),
            "path": "project.yaml",
            "pointer": "/provider",
        }
    ]


def test_compile_check_preserves_legacy_auth_warning(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("compile", "--check", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="compile",
        ok=True,
        allow_warnings=True,
    )
    assert [item["code"] for item in payload["diagnostics"]] == ["ACC_AUTH_LEGACY_CREDENTIAL"]


def test_successful_default_output_writes_warnings_to_stderr(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("validate", cwd=project)

    assert completed.returncode == 0
    assert "validate: ok" in completed.stdout
    assert "ACC_AUTH_LEGACY_CREDENTIAL" in completed.stderr


@pytest.mark.parametrize("json_output", [False, True])
def test_pack_success_preserves_compile_warnings(
    tmp_path: Path,
    json_output: bool,
) -> None:
    project = _make_valid_project(tmp_path)
    arguments = ["pack", "--output", "build/test.accpkg"]
    if json_output:
        arguments.append("--json")

    completed = _run_acc(*arguments, cwd=project)

    assert completed.returncode == 0, completed.stderr
    if json_output:
        payload = _json_envelope(
            completed,
            command="pack",
            ok=True,
            allow_warnings=True,
        )
        assert [item["code"] for item in payload["diagnostics"]] == ["ACC_AUTH_LEGACY_CREDENTIAL"]
    else:
        assert "pack: ok" in completed.stdout
        assert "ACC_AUTH_LEGACY_CREDENTIAL" in completed.stderr


def test_coverage_success_preserves_validation_warning(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)

    completed = _run_acc("coverage", "--json", cwd=project)

    assert completed.returncode == 0, completed.stderr
    payload = _json_envelope(
        completed,
        command="coverage",
        ok=True,
        allow_warnings=True,
    )
    assert [item["code"] for item in payload["diagnostics"]] == ["ACC_AUTH_LEGACY_CREDENTIAL"]


def test_validate_rejects_an_operation_without_evidence(tmp_path: Path) -> None:
    project = _make_valid_project(tmp_path)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["evidence"] = []
    _write_yaml(operation_path, operation)

    completed = _run_acc("validate", "--json", cwd=project)

    assert completed.returncode == 3
    payload = _json_envelope(completed, command="validate", ok=False)
    assert payload["diagnostics"][0] == {
        "code": "ACC_OPERATION_EVIDENCE_MISSING",
        "severity": "error",
        "message": "Operation requires at least one evidence reference.",
        "path": "operations/crm.get_customer.yaml",
        "pointer": "/evidence",
    }


def test_cli_usage_error_has_json_envelope_and_exit_code_two() -> None:
    completed = _run_acc("validate", "--unknown-option", "--json")

    assert completed.returncode == 2
    payload = _json_envelope(completed, command="validate", ok=False)
    assert payload["diagnostics"][0]["code"] == "ACC_CLI_USAGE"
    assert payload["diagnostics"][0]["severity"] == "error"


def test_adapter_init_creates_isolated_read_only_adapter_skeleton(tmp_path: Path) -> None:
    target = tmp_path / "customer-adapter"

    completed = _run_acc("adapter", "init", str(target), "--json")

    payload = _json_envelope(completed, command="adapter init", ok=True)
    assert payload["result"]["path"] == str(target.resolve())
    assert (target / "pyproject.toml").is_file()
    assert (target / "contract.yaml").is_file()
    main = (target / "src" / "customer_adapter" / "main.py").read_text(encoding="utf-8")
    assert "AdapterServer" in main
    assert "POST" not in main

    repeated = _run_acc("adapter", "init", str(target), "--json")
    repeated_payload = _json_envelope(repeated, command="adapter init", ok=False)
    assert repeated.returncode == 3
    assert repeated_payload["diagnostics"][0]["code"] == "ACC_ADAPTER_EXISTS"

    occupied_file = tmp_path / "occupied"
    occupied_file.write_text("keep", encoding="utf-8")
    occupied = _run_acc("adapter", "init", str(occupied_file), "--json")
    occupied_payload = _json_envelope(occupied, command="adapter init", ok=False)
    assert occupied.returncode == 3
    assert occupied_payload["diagnostics"][0]["code"] == "ACC_ADAPTER_EXISTS"
    assert occupied_file.read_text(encoding="utf-8") == "keep"
