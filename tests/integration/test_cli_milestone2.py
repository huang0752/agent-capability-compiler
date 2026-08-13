from __future__ import annotations

import argparse
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

from acc_core.cli.main import _parser
from acc_core.packaging import verify_pack
from acc_testkit.live import LiveGatewayReport, LiveStepResult, LiveStepStatus

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
            "schema_version": "2",
            "project": {"id": "example-crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "CRM_BASE_URL",
                "auth": {"kind": "bearer_secret", "token_ref": "CRM_USER_TOKEN"},
                "context_binding_allowlist": ["tenant_context.tenant_id"],
            },
            "quality": {"profile": "standard"},
        },
    )
    _write_yaml(
        project / "operations" / "crm.get_customer.yaml",
        {
            "schema_version": "2",
            "id": "crm.get_customer",
            "title": "Get customer",
            "kind": "read",
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
                "query_parameters": {"tenant_id": "tenant_id"},
                "scopes": ["customer.read"],
                "timeout_seconds": 15,
                "max_response_bytes": 1048576,
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "safety": {
                    "effect": "read",
                    "risk": "low",
                    "reversibility": "reversible",
                    "retry": {"mode": "idempotent_only"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "context_bindings": {"tenant_id": "tenant_context.tenant_id"},
            "evidence": [
                {
                    "source_id": "crm-backend",
                    "kind": "source_file",
                    "path": "routes.py",
                    "line_start": 1,
                    "line_end": 1,
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        },
    )
    _write_yaml(
        project / "policies" / "crm-read.yaml",
        {
            "schema_version": "2",
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
            "schema_version": "2",
            "kind": "read",
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
                "schema_version": "2",
                "id": eval_id,
                "capability": "get_customer",
                "input": {"customer_id": "c-1"},
                "fixtures": {"runtime_context": runtime_context},
                "expected_calls": expected_calls,
                "forbidden_fields": ["internal_note"],
                **expected,
            },
        )
    _write_yaml(
        project / "source-contracts" / "crm.get_customer.yaml",
        {
            "schema_version": "2",
            "id": "crm.get_customer.contract",
            "operation_id": "crm.get_customer",
            "request_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "customer_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                },
            },
            "response_schema": {"type": "object"},
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
        },
    )
    _write_yaml(
        project / "capability-quality" / "get_customer.yaml",
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "intent": {"action": "get", "resource_types": ["customer"]},
            "inputs": {
                "customer_id": {
                    "kind": "resource_selector",
                    "resource_type": "customer",
                    "acquisition": "caller",
                }
            },
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65536, "long_text_disclosures": []},
        },
    )
    _write_yaml(
        project / "scope-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {"mode": "system_complete", "exclusion_approval": {}},
            "discovery": {
                "source_commit": "git:0123456789abcdef",
                "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
                "include_paths": ["routes.py"],
                "evidence_sources": ["routes.py"],
            },
            "domains": [{"id": "crm", "status": "selected"}],
            "routes": [
                {
                    "id": "GET /customers/{customer_id}",
                    "domain": "crm",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/customers/{customer_id}",
                    "evidence_sources": ["routes.py"],
                    "eligibility": "eligible",
                    "disposition": "composed",
                    "operation_id": "crm.get_customer",
                    "capability_ids": ["get_customer"],
                }
            ],
            "summary": {
                "discovered_routes": 1,
                "eligible_routes": 1,
                "planned": 0,
                "composed": 1,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
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
    assert coverage["result"]["operation_trace"]["traced_route_ids"] == [
        "GET /customers/{customer_id}"
    ]
    interaction_axes = [
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
    ]
    assert [axis for axis in interaction_axes if axis in coverage["result"]] == interaction_axes
    assert coverage["result"]["surface_disposition"]["status"] == "not_declared"
    assert coverage["result"]["client_adapter_evidence"]["status"] == "not_declared"
    assert "score" not in json.dumps(coverage["result"], sort_keys=True)

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
        "scope_analysis": {
            "deployment_scope_ceiling": [],
            "summary": {"callable": 0, "conditional": 0, "denied": 1},
            "capabilities": [
                {
                    "capability": "get_customer",
                    "always_required": ["customer.read"],
                    "conditionally_required": [],
                    "all_referenced": ["customer.read"],
                    "completion_alternatives": [["customer.read"]],
                    "deployment": {
                        "status": "denied",
                        "available_scopes": [],
                        "missing_always": ["customer.read"],
                        "missing_conditional": [],
                        "unmet_alternatives": [["customer.read"]],
                    },
                    "user": {
                        "status": "unknown",
                        "available_scopes": None,
                        "missing_always": [],
                        "missing_conditional": [],
                        "unmet_alternatives": [],
                    },
                    "effective": {
                        "status": "unknown",
                        "available_scopes": None,
                        "missing_always": [],
                        "missing_conditional": [],
                        "unmet_alternatives": [],
                    },
                }
            ],
        },
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
    assert [item["code"] for item in runtime["diagnostics"]] == [
        "ACC_RUN_SCOPE_CEILING_EMPTY",
        "ACC_RUN_CAPABILITY_SCOPE_DENIED",
    ]

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


def _live_profile(pack_sha256: str) -> dict[str, object]:
    return {
        "attestation": {
            "pack_sha256": pack_sha256,
            "project_id": "example-crm",
            "project_version": "0.1.0",
            "interaction_sha256": "c" * 64,
            "tool_schema_sha256": "b" * 64,
        },
        "accounts": [
            {
                "alias": "a",
                "identity": {"env": "LIVE_A_IDENTITY"},
                "password": {"env": "LIVE_A_PASSWORD"},
            },
            {
                "alias": "b",
                "identity": {"env": "LIVE_B_IDENTITY"},
                "password": {"env": "LIVE_B_PASSWORD"},
            },
        ],
        "cases": [
            {
                "id": "generic-read",
                "account": "a",
                "tool": "get_customer",
                "capability_id": "get_customer",
                "arguments": {},
            }
        ],
        "isolation": {
            "accounts": ["a", "b"],
            "tool": "records.current",
            "arguments": {},
            "expected_structured_content": {
                "a": {"result": {"owner": "a"}},
                "b": {"result": {"owner": "b"}},
            },
        },
    }


def _live_arguments(
    pack_path: Path,
    profile_path: Path,
    *,
    gateway_url: str = "http://127.0.0.1:8765",
    allow_source_connect: bool = True,
    allowed_gateway_host: str | None = None,
    observations_output: Path | None = None,
) -> argparse.Namespace:
    arguments = [
        "test",
        "live",
        str(pack_path),
        "--gateway-url",
        gateway_url,
        "--profile",
        str(profile_path),
        "--json",
    ]
    if allow_source_connect:
        arguments.append("--allow-source-connect")
    if allowed_gateway_host is not None:
        arguments.extend(["--allowed-gateway-host", allowed_gateway_host])
    if observations_output is not None:
        arguments.extend(["--observations-output", str(observations_output)])
    return _parser().parse_args(arguments)


def _make_live_pack_and_profile(tmp_path: Path) -> tuple[Path, Path]:
    project = _make_project(tmp_path)
    packed = _payload(_run_acc("pack", "--output", "live.accpkg", "--json", cwd=project))
    pack_path = Path(packed["result"]["path"])
    profile_path = project / "live-tests.yaml"
    _write_yaml(profile_path, _live_profile(verify_pack(pack_path).sha256))
    return pack_path, profile_path


def test_live_cli_requires_explicit_source_connection_authorization(tmp_path: Path) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)

    arguments = _live_arguments(
        pack_path,
        profile_path,
        allow_source_connect=False,
    )
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.ok is False
    assert envelope.diagnostics[0].code == "ACC_LIVE_SOURCE_CONNECT_NOT_ALLOWED"


@pytest.mark.parametrize(
    "gateway_url",
    [
        "http://user:password@127.0.0.1:8765",
        "http://127.0.0.1:8765?token=private",
        "http://127.0.0.1:8765/#private",
    ],
)
def test_live_cli_rejects_secret_bearing_or_ambiguous_gateway_urls(
    tmp_path: Path,
    gateway_url: str,
) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)

    arguments = _live_arguments(pack_path, profile_path, gateway_url=gateway_url)
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.diagnostics[0].code == "ACC_LIVE_GATEWAY_URL_INVALID"


def test_live_cli_requires_exact_allowlist_for_non_loopback_gateway(tmp_path: Path) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)

    arguments = _live_arguments(
        pack_path,
        profile_path,
        gateway_url="https://gateway.example.test:8443",
    )
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.diagnostics[0].code == "ACC_LIVE_GATEWAY_NOT_ALLOWED"


def test_live_cli_json_missing_profile_secret_is_a_stable_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)
    monkeypatch.delenv("LIVE_A_IDENTITY", raising=False)
    monkeypatch.delenv("LIVE_A_PASSWORD", raising=False)
    monkeypatch.delenv("LIVE_B_IDENTITY", raising=False)
    monkeypatch.delenv("LIVE_B_PASSWORD", raising=False)

    arguments = _live_arguments(
        pack_path,
        profile_path,
        gateway_url="https://gateway.example.test:8443",
        allowed_gateway_host="gateway.example.test:8443",
    )
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.ok is False
    assert envelope.diagnostics[0].code == "ACC_LIVE_SECRET_MISSING"


def test_live_cli_invokes_runner_and_returns_structured_verification_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)
    for name in (
        "LIVE_A_IDENTITY",
        "LIVE_A_PASSWORD",
        "LIVE_B_IDENTITY",
        "LIVE_B_PASSWORD",
    ):
        monkeypatch.setenv(name, f"{name}-private")
    expected = LiveGatewayReport.from_steps(
        [
            LiveStepResult(
                id="runtime.attestation",
                required=True,
                status=LiveStepStatus.PASSED,
            )
        ],
        pack_sha256=verify_pack(pack_path).sha256,
    )
    called: list[str] = []

    async def fake_execute(profile: object, environment: object) -> LiveGatewayReport:
        del environment
        called.append(type(profile).__name__)
        return expected

    monkeypatch.setattr("acc_core.cli.live._execute_live_profile", fake_execute)
    arguments = _live_arguments(pack_path, profile_path)
    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 0
    assert envelope.ok is True
    assert envelope.command == "test live"
    assert envelope.result == expected.model_dump(mode="json")
    assert called == ["LiveGatewayProfile"]


def test_live_cli_artifact_is_consumed_by_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)
    for name in (
        "LIVE_A_IDENTITY",
        "LIVE_A_PASSWORD",
        "LIVE_B_IDENTITY",
        "LIVE_B_PASSWORD",
    ):
        monkeypatch.setenv(name, f"{name}-private")
    expected = LiveGatewayReport.from_steps(
        [
            LiveStepResult(
                id="runtime.attestation",
                required=True,
                status=LiveStepStatus.PASSED,
            ),
            LiveStepResult(
                id="case.generic-read",
                required=True,
                status=LiveStepStatus.PASSED,
                evidence={"response_bytes": 321},
            ),
        ],
        pack_sha256=verify_pack(pack_path).sha256,
    )

    async def fake_execute(profile: object, environment: object) -> LiveGatewayReport:
        del profile, environment
        return expected

    monkeypatch.setattr("acc_core.cli.live._execute_live_profile", fake_execute)
    artifact_path = tmp_path / "live-observations.json"
    live_arguments = _live_arguments(
        pack_path,
        profile_path,
        observations_output=artifact_path,
    )

    live_exit, live_envelope = live_arguments.handler(live_arguments)
    coverage_arguments = _parser().parse_args(
        [
            "coverage",
            str(pack_path.parent),
            "--live-observations",
            str(artifact_path),
            "--live-pack",
            str(pack_path),
            "--json",
        ]
    )
    coverage_exit, coverage_envelope = coverage_arguments.handler(coverage_arguments)

    assert live_exit == 0
    assert live_envelope.ok is True
    assert artifact_path.is_file()
    assert coverage_exit == 0
    assert coverage_envelope.ok is True
    assert coverage_envelope.result is not None
    observations = coverage_envelope.result["live_observations"]
    assert observations["status"] == "observed"
    assert observations["observations"] == [
        {
            "capability_id": "get_customer",
            "verification_level": "source_connected_verified",
            "sample_count": 1,
            "response_bytes_p50": 321,
            "response_bytes_p95": 321,
            "response_bytes_max": 321,
        }
    ]


def test_live_cli_unverified_report_is_a_failed_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack_path, profile_path = _make_live_pack_and_profile(tmp_path)
    for name in (
        "LIVE_A_IDENTITY",
        "LIVE_A_PASSWORD",
        "LIVE_B_IDENTITY",
        "LIVE_B_PASSWORD",
    ):
        monkeypatch.setenv(name, f"{name}-private")
    expected = LiveGatewayReport.from_steps(
        [
            LiveStepResult(
                id="runtime.attestation",
                required=True,
                status=LiveStepStatus.FAILED,
            )
        ],
        pack_sha256=verify_pack(pack_path).sha256,
    )

    async def fake_execute(profile: object, environment: object) -> LiveGatewayReport:
        del profile, environment
        return expected

    monkeypatch.setattr("acc_core.cli.live._execute_live_profile", fake_execute)
    arguments = _live_arguments(pack_path, profile_path)

    exit_code, envelope = arguments.handler(arguments)

    assert exit_code == 5
    assert envelope.ok is False
    assert envelope.result is None
    assert envelope.diagnostics[0].code == "ACC_LIVE_VERIFICATION_INCOMPLETE"
    assert envelope.diagnostics[0].severity == "error"


def test_run_inspects_streamable_http_gateway_without_starting_server(tmp_path: Path) -> None:
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
    operation["http"].pop("credential_ref", None)
    _write_yaml(operation_path, operation)
    packed = _payload(_run_acc("pack", "--output", "gateway.accpkg", "--json", cwd=project))

    completed = _run_acc(
        "run",
        packed["result"]["path"],
        "--allowed-host",
        "127.0.0.1:8000",
        "--json",
        cwd=project,
        environment={"CRM_BASE_URL": "http://127.0.0.1:9"},
    )

    payload = _payload(completed)
    assert payload["result"]["transport"] == "streamable_http"
    assert payload["result"]["gateway"] == {
        "allowed_hosts": ["127.0.0.1:8000"],
        "allowed_origins": [],
        "host": "127.0.0.1",
        "max_request_body_size": 4 * 1024 * 1024,
        "max_sessions": 1000,
        "mcp_session_idle_timeout_seconds": 60.0,
        "port": 8000,
        "scope_mode": "deployment_ceiling",
        "session_ttl_seconds": 3600,
        "tls_enabled": False,
        "workers": 1,
    }


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
    operation["http"].pop("credential_ref", None)
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
    assert error_output.splitlines() == [
        (
            "ACC_RUN_SCOPE_CEILING_EMPTY: The deployment scope ceiling is empty while the Pack "
            "declares scoped capabilities."
        ),
        (
            "ACC_RUN_CAPABILITY_SCOPE_DENIED: Capability get_customer has no callable path under "
            "the deployment scope ceiling."
        ),
    ]


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
