from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


def _run_acc(
    *arguments: str,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    process_environment = os.environ.copy()
    process_environment.update(environment or {})
    process_environment["PYTHONPATH"] = os.pathsep.join(
        [str(ACC_CORE_SRC), process_environment.get("PYTHONPATH", "")]
    )
    return subprocess.run(
        [sys.executable, "-m", "acc_core.cli.main", *arguments],
        cwd=cwd,
        env=process_environment,
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
                "properties": {
                    "customer_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                },
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
            "policy": "crm-read",
            "evals": ["normal", "forbidden"],
        },
    )
    for eval_id, expected, runtime_context, expected_calls in (
        (
            "normal",
            {"expected_output_schema": {"type": "object"}},
            {"granted_scopes": ["customer.read"], "tenant_id": "tenant-a"},
            [
                {
                    "operation": "crm.get_customer",
                    "arguments": {"customer_id": "c-1", "tenant_id": "tenant-a"},
                }
            ],
        ),
        (
            "forbidden",
            {
                "expected_error": {
                    "code": "ACC_RUNTIME_POLICY_SCOPE_DENIED",
                    "status": 403,
                }
            },
            {"granted_scopes": [], "tenant_id": "tenant-a"},
            [],
        ),
    ):
        _write_yaml(
            project / "evals" / f"{eval_id}.yaml",
            {
                "schema_version": "1",
                "id": eval_id,
                "capability": "get_customer",
                "input": {"customer_id": "c-1"},
                "fixtures": {"runtime_context": runtime_context},
                "expected_calls": expected_calls,
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
                "input_schema": {
                    "additionalProperties": False,
                    "properties": {"customer_id": {"type": "string"}},
                    "required": ["customer_id"],
                    "type": "object",
                },
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


def test_run_rejects_streamable_http_until_gateway_phase(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    project_path = project / "project.yaml"
    document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    document["runtime"]["transport"] = ["streamable_http"]
    document["provider"]["auth"] = {
        "kind": "password_bearer",
        "credentials": {"kind": "gateway_session"},
        "login_path": "/auth/login",
        "identity_field": "username",
        "password_field": "password",
        "token_pointer": "/access_token",
        "scopes_pointer": "/permissions",
        "scope_mapping": {"customer:read": ["customer.read"]},
    }
    _write_yaml(project_path, document)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["http"].pop("credential_ref")
    _write_yaml(operation_path, operation)
    packed = _payload(_run_acc("pack", "--output", "gateway.accpkg", "--json", cwd=project))

    completed = _run_acc(
        "run",
        packed["result"]["path"],
        "--json",
        cwd=project,
        environment={"CRM_BASE_URL": "http://127.0.0.1:9"},
    )

    assert completed.returncode == 6
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert payload["diagnostics"] == [
        {
            "code": "ACC_RUNTIME_CONFIGURATION_INVALID",
            "message": "Streamable HTTP packs require the ACC Gateway.",
            "path": None,
            "pointer": None,
            "severity": "error",
        }
    ]


def test_contract_eval_cli_returns_structured_case_report(tmp_path: Path) -> None:
    project = _make_project(tmp_path)

    completed = _run_acc("test", "contract", "--json", cwd=project)

    payload = _payload(completed)
    assert payload["command"] == "test contract"
    assert payload["result"]["kind"] == "contract"
    assert payload["result"]["summary"] == {"total": 2, "passed": 2, "failed": 0}
    assert [case["id"] for case in payload["result"]["cases"]] == ["forbidden", "normal"]


@contextmanager
def _fake_crm_server() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("authorization") != "Bearer test-token":
                self.send_response(401)
                self.end_headers()
                return
            body = (
                b'{"id":"c-1","name":"Example","tenant_id":"tenant-a",'
                b'"internal_note":"must-be-filtered"}'
            )
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = cast(tuple[str, int], server.server_address)
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_runtime_and_e2e_eval_cli_execute_declared_cases(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    with _fake_crm_server() as base_url:
        environment = {
            "CRM_BASE_URL": base_url,
            "CRM_USER_TOKEN": "test-token",
            "ACC_GRANTED_SCOPES": "customer.read",
            "ACC_TENANT_ID": "tenant-a",
        }
        for suite in ("runtime", "e2e"):
            completed = _run_acc(
                "test",
                suite,
                "--json",
                cwd=project,
                environment=environment,
            )
            payload = _payload(completed)
            assert payload["command"] == f"test {suite}"
            assert payload["result"]["summary"] == {
                "total": 2,
                "passed": 2,
                "failed": 0,
            }


@contextmanager
def _fake_provider_auth_server(auth_kind: str) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if auth_kind != "password_bearer" or self.path != "/auth/login":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length))
            if body != {"username": "test-user", "password": "test-password"}:
                self.send_response(401)
                self.end_headers()
                return
            response = b'{"access_token":"test-token"}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def do_GET(self) -> None:
            expected = None if auth_kind == "none" else "Bearer test-token"
            if self.headers.get("authorization") != expected:
                self.send_response(401)
                self.end_headers()
                return
            body = (
                b'{"id":"c-1","name":"Example","tenant_id":"tenant-a",'
                b'"internal_note":"must-be-filtered"}'
            )
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = cast(tuple[str, int], server.server_address)
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _use_provider_auth(project: Path, auth_kind: str) -> None:
    project_path = project / "project.yaml"
    document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    if auth_kind == "none":
        auth: dict[str, object] = {"kind": "none"}
    elif auth_kind == "bearer_secret":
        auth = {"kind": "bearer_secret", "token_ref": "CRM_USER_TOKEN"}
    else:
        auth = {
            "kind": "password_bearer",
            "credentials": {
                "kind": "environment_secret",
                "identity_ref": "CRM_USER",
                "password_ref": "CRM_PASSWORD",
            },
            "login_path": "/auth/login",
            "identity_field": "username",
            "password_field": "password",
            "token_pointer": "/access_token",
        }
    document["provider"]["auth"] = auth
    _write_yaml(project_path, document)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    operation = yaml.safe_load(operation_path.read_text(encoding="utf-8"))
    operation["http"].pop("credential_ref")
    _write_yaml(operation_path, operation)


@pytest.mark.parametrize("auth_kind", ["none", "bearer_secret", "password_bearer"])
def test_runtime_and_e2e_eval_cli_support_provider_auth(
    tmp_path: Path,
    auth_kind: str,
) -> None:
    project = _make_project(tmp_path)
    _use_provider_auth(project, auth_kind)
    with _fake_provider_auth_server(auth_kind) as base_url:
        environment = {
            "CRM_BASE_URL": base_url,
            "CRM_USER_TOKEN": "test-token",
            "CRM_USER": "test-user",
            "CRM_PASSWORD": "test-password",
            "ACC_GRANTED_SCOPES": "customer.read",
            "ACC_TENANT_ID": "tenant-a",
        }
        for suite in ("runtime", "e2e"):
            completed = _run_acc(
                "test",
                suite,
                "--json",
                cwd=project,
                environment=environment,
            )

            payload = _payload(completed)
            assert payload["result"]["summary"] == {
                "total": 2,
                "passed": 2,
                "failed": 0,
            }


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
