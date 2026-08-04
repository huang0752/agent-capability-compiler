from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryFile
from typing import Any, cast

import pytest
import yaml
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from acc_core.packaging import verify_pack

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACC_CORE_SRC = REPOSITORY_ROOT / "packages" / "acc-core" / "src"


def _run_acc(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(ACC_CORE_SRC), environment.get("PYTHONPATH", "")]
    )
    return subprocess.run(
        [sys.executable, "-m", "acc_core.cli.main", *arguments],
        cwd=cwd,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )


def _payload(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert completed.returncode == 0, completed.stderr or completed.stdout
    value = json.loads(completed.stdout)
    assert value["ok"] is True
    return cast(dict[str, Any], value)


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _make_project(root: Path) -> Path:
    project = root / "acc-project"
    source = root / "system"
    source.mkdir()
    (source / "routes.py").write_text("def get_customer(): ...\n", encoding="utf-8")
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
                "max_response_bytes": 1048576,
            },
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": "crm-backend",
                    "locator": "routes.py#L1-L1",
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        },
    )
    _write_yaml(
        project / "policies" / "crm-read.yaml",
        {
            "schema_version": "1",
            "id": "crm-read",
            "required_scopes": ["customer.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["id", "name"],
            "denied_fields": ["internal_note"],
            "redaction_rules": [],
        },
    )
    _write_yaml(
        project / "capabilities" / "get_customer.yaml",
        {
            "schema_version": "1",
            "id": "get_customer",
            "title": "Get customer",
            "description": "Get one visible customer.",
            "input_schema": {"type": "object", "additionalProperties": False},
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
            "policy": "crm-read",
            "evals": ["normal", "forbidden"],
        },
    )
    for eval_id, expected in (
        ("normal", {"expected_output_schema": {"type": "object"}}),
        ("forbidden", {"expected_error": {"code": "FORBIDDEN", "status": 403}}),
    ):
        _write_yaml(
            project / "evals" / f"{eval_id}.yaml",
            {
                "schema_version": "1",
                "id": eval_id,
                "capability": "get_customer",
                "input": {"customer_id": "c-1"},
                "fixtures": {},
                "expected_calls": [
                    {"operation": "crm.get_customer", "arguments": {"customer_id": "c-1"}}
                ],
                "forbidden_fields": ["internal_note"],
                **expected,
            },
        )
    return project


def test_milestone_two_cli_compiles_analyzes_packs_diffs_and_freezes(tmp_path: Path) -> None:
    project = _make_project(tmp_path)

    checked = _payload(_run_acc("compile", "--check", "--json", cwd=project))
    assert checked["command"] == "compile"
    assert checked["result"]["project_id"] == "example-crm"

    compiled = _payload(_run_acc("compile", "--output", "build/ir.json", "--json", cwd=project))
    ir_path = Path(compiled["result"]["path"])
    assert ir_path.is_file()

    coverage = _payload(_run_acc("coverage", "--json", cwd=project))
    assert coverage["result"]["summary"]["capabilities"] == 1

    diffed = _payload(_run_acc("diff", str(ir_path), str(ir_path), "--json", cwd=project))
    assert diffed["result"]["has_changes"] is False

    packed = _payload(_run_acc("pack", "--output", "example-crm.accpkg", "--json", cwd=project))
    pack_path = Path(packed["result"]["path"])
    verification = verify_pack(pack_path)
    assert verification.manifest.project_id == "example-crm"
    assert "compiled/ir.json" in {record.path for record in verification.files}

    runtime = _payload(_run_acc("run", str(pack_path), "--json", cwd=project))
    assert runtime["command"] == "run"
    assert runtime["result"] == {
        "pack": str(pack_path.resolve()),
        "tools": [
            {
                "description": "Get one visible customer.",
                "input_schema": {"additionalProperties": False, "type": "object"},
                "name": "get_customer",
                "output_schema": {"type": "object"},
                "title": "Get customer",
            }
        ],
        "transport": "stdio",
    }

    before = (project / "operations" / "crm.get_customer.yaml").read_text(encoding="utf-8")
    frozen = _payload(_run_acc("freeze", "crm.get_customer", "--json", cwd=project))
    after = (project / "operations" / "crm.get_customer.yaml").read_text(encoding="utf-8")
    assert frozen["result"]["updated"] == 1
    assert before != after
    assert f"sha256:{'0' * 64}" not in after


def test_run_reports_pack_failures_as_stable_json(tmp_path: Path) -> None:
    completed = _run_acc("run", str(tmp_path / "missing.accpkg"), "--json", cwd=tmp_path)

    assert completed.returncode == 6
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert payload["diagnostics"][0]["code"] == "ACC_RUNTIME_PACK_VERIFICATION_FAILED"


@pytest.mark.asyncio
async def test_run_serves_real_mcp_stdio_tool_listing(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    packed = _payload(_run_acc("pack", "--output", "runtime.accpkg", "--json", cwd=project))
    pack_path = Path(packed["result"]["path"])
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(ACC_CORE_SRC), environment.get("PYTHONPATH", "")]
    )
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "acc_core.cli.main", "run", str(pack_path)],
        env=environment,
        cwd=project,
    )
    with TemporaryFile(mode="w+", encoding="utf-8") as error_log:
        async with (
            stdio_client(server, errlog=error_log) as streams,
            ClientSession(*streams) as session,
        ):
            initialized = await session.initialize()
            result = await session.list_tools()
        error_log.seek(0)
        error_output = error_log.read()

    assert initialized.serverInfo.name == "acc-runtime"
    assert [tool.name for tool in result.tools] == ["get_customer"]
    assert error_output == ""


def test_compile_refuses_to_overwrite_project_contracts(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    project_file = project / "project.yaml"
    before = project_file.read_bytes()

    completed = _run_acc(
        "compile",
        "--output",
        "project.yaml",
        "--json",
        cwd=project,
    )

    assert completed.returncode == 4
    payload = json.loads(completed.stdout)
    assert payload["diagnostics"][0]["code"] == "ACC_COMPILE_OUTPUT_FAILED"
    assert project_file.read_bytes() == before
