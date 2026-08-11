from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import json
import os
import shutil
import sys
import zipfile
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from tempfile import TemporaryFile

import httpx
import pytest
import yaml
from mcp.client.stdio import StdioServerParameters
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import TextResourceContents
from pydantic import AnyUrl, JsonValue
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from acc_core.packaging import build_pack
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage.acceptance import (
    listed_tool_snapshot_sha256,
    verify_mcp_release_acceptance,
)
from acc_core.usage.models import McpReleaseAcceptance, usage_domain_decision_digest
from acc_core.usage.packaging import (
    UsagePackageSigner,
    UsagePackageTrustStore,
    build_usage_package,
)
from acc_core.usage.project import validate_usage_project
from acc_core.usage.verification import VerifiedUsageReleaseBundle
from acc_runtime.credentials import SecretValue
from acc_runtime.mcp import CapabilityMcpServer
from acc_runtime.usage import AgentUsageOverlayMcpServer
from acc_testkit import McpStdioTestClient, McpStreamableHttpTestClient
from acc_testkit.usage import (
    AgentUsageReleaseVerifier,
    RealMcpUsageRunner,
    UsageAttestation,
    UsageScenarioVerification,
    UsageToolOutcome,
    usage_contract_digest,
    usage_scenario_digest,
)

pytestmark = pytest.mark.e2e
ROOT = Path(__file__).resolve().parents[2]
_SIGNING_KEY = b"overlay-test-signing-root-material-32-bytes"
_SIGNER = UsagePackageSigner(_SIGNING_KEY)
_TRUST_STORE = UsagePackageTrustStore({_SIGNER.key_id: _SIGNING_KEY})


class _Runtime:
    def tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": "finance_invoice_list",
                "title": "List invoices",
                "description": "List current invoices.",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
                "output_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["items"],
                    "properties": {"items": {"type": "array", "items": {}}},
                },
            }
        ]

    def interaction_manifest(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "2",
            "digest": "0" * 64,
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        }

    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        return {"items": []}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def _prepare_verified_project(root: Path, base: CapabilityMcpServer) -> None:
    client = _BundleClient(base)
    input_schema = client._tools[0]["inputSchema"]
    output_wrapper = client._tools[0]["outputSchema"]
    assert isinstance(output_wrapper, dict)
    output_properties = output_wrapper.get("properties")
    assert isinstance(output_properties, dict)
    output_schema = output_properties["result"]
    interaction = {
        "schema_version": "2",
        "inventory": {"status": "declared"},
        "contracts": {"finance_invoice_list": {}},
        "dependencies": [],
    }
    interaction_digest = hashlib.sha256(canonical_json_bytes(interaction)).hexdigest()
    compiled_ir = {
        "ir_version": "2",
        "project": {
            "schema_version": "2",
            "project": {"id": "finance-usage", "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "FINANCE_BASE_URL"},
            "quality": {"profile": "standard"},
        },
        "interaction_sha256": interaction_digest,
        "interactions": {**interaction, "digest": interaction_digest},
        "capabilities": {
            "finance_invoice_list": {
                "definition": {
                    "kind": "read",
                    "input_schema": input_schema,
                    "output_schema": output_schema,
                }
            }
        },
        "operations": {},
        "policies": {},
        "evals": {},
    }
    pack_project = root.parent / "acc-project"
    pack_project.mkdir()
    (pack_project / "project.yaml").write_text(
        yaml.safe_dump(compiled_ir["project"], sort_keys=False), encoding="utf-8"
    )
    (pack_project / "domain-map.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "2",
                "domains": [
                    {
                        "id": "finance",
                        "title": "Finance",
                        "status": "in_progress",
                        "candidate_ids": [],
                        "route_ids": [],
                        "interaction_ids": [],
                        "dependency_domain_ids": [],
                        "evidence_refs": [],
                        "active_decision_ref": None,
                    }
                ],
                "unclassified_candidate_ids": [],
                "preferred_order": ["finance"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    pack_path = root.parent / "finance.accpkg"
    build_pack(pack_project, pack_path, compiled_ir=compiled_ir)
    with zipfile.ZipFile(pack_path) as archive:
        ir_bytes = archive.read("compiled/ir.json")
    report_path = root.parent / "test-report.json"
    report_path.write_text('{"passed":true}\n', encoding="utf-8")
    baseline = {
        "pack_digest": "sha256:" + hashlib.sha256(pack_path.read_bytes()).hexdigest(),
        "ir_digest": "sha256:" + hashlib.sha256(ir_bytes).hexdigest(),
        "tool_schema_digest": "sha256:" + listed_tool_snapshot_sha256({"tools": client._tools}),
        "test_report_digest": "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest(),
    }
    for relative in (
        "mcp-release-acceptance.yaml",
        "domain-index.yaml",
        "domain-usage-contracts/finance.yaml",
        "releases/finance-1.yaml",
    ):
        path = root / relative
        value = yaml.safe_load(path.read_text())
        for key, digest in baseline.items():
            if key in value:
                value[key] = digest
        path.write_text(yaml.safe_dump(value, sort_keys=False))
    contract_path = root / "domain-usage-contracts/finance.yaml"
    contract = yaml.safe_load(contract_path.read_text())
    contract["tool_routes"][0]["steps"][0]["capability_id"] = "finance_invoice_list"
    contract["result_consumption"][0]["capability_id"] = "finance_invoice_list"
    contract["error_handling"] = [
        {
            "id": "http-errors",
            "outcomes": ["forbidden", "not_found", "timeout", "unauthorized"],
            "behavior": "stop",
            "description": "Stop on source HTTP failures.",
            "step_ids": ["list"],
            "retry_policy": "never",
            "evidence_claim_ids": ["claim-result"],
        }
    ]
    contract["tool_routes"][0]["error_branch_ids"] = ["http-errors"]
    contract_path.write_text(yaml.safe_dump(contract, sort_keys=False))
    contract_digest = _canonical_digest(contract)
    decision_path = root / "domain-decisions/finance-1.yaml"
    decision = yaml.safe_load(decision_path.read_text())
    decision["contract_digest"] = contract_digest
    decision["decision_digest"] = usage_domain_decision_digest(decision)
    decision["user_confirmation"]["confirmed_decision_digest"] = decision["decision_digest"]
    decision["user_confirmation"]["source_text_digest"] = "sha256:" + "f" * 64
    decision_path.write_text(yaml.safe_dump(decision, sort_keys=False))
    release_path = root / "releases/finance-1.yaml"
    release = yaml.safe_load(release_path.read_text())
    release["contract_digest"] = contract_digest
    release["decision_digest"] = decision["decision_digest"]
    release["capability_ids"] = ["finance_invoice_list"]
    release["verification"]["host_adapter_verified"] = False
    release["host_adapters"] = []
    release_path.write_text(yaml.safe_dump(release, sort_keys=False))


def _usage_package(tmp_path: Path, base: CapabilityMcpServer) -> Path:
    root = tmp_path / "usage-project"
    shutil.copytree(Path("tests/fixtures/usage/finance"), root)
    _prepare_verified_project(root, base)
    output = tmp_path / "finance.accusage"
    bundle = asyncio.run(_verified_bundle(root, base))
    build_usage_package(root, output, verified_releases=(bundle,), signer=_SIGNER)
    return output


class _BundleClient:
    def __init__(self, base: CapabilityMcpServer) -> None:
        self._tools: list[dict[str, object]] = [
            {
                "name": tool.name,
                "inputSchema": dict(tool.inputSchema),
                "outputSchema": dict(tool.outputSchema or {}),
            }
            for tool in base.list_tools()
        ]

    async def list_tools(self) -> list[dict[str, object]]:
        return self._tools

    async def call(self, tool_name: str, arguments: object) -> UsageToolOutcome:
        assert tool_name == "finance_invoice_list"
        assert arguments == {}
        return UsageToolOutcome.success({"items": []})


async def _verified_bundle(root: Path, base: CapabilityMcpServer) -> VerifiedUsageReleaseBundle:
    project = validate_usage_project(root)
    assert project.ok
    client = _BundleClient(base)
    acceptance = McpReleaseAcceptance.model_validate(
        yaml.safe_load((root / "mcp-release-acceptance.yaml").read_text())
    )
    accepted = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=root.parent / "finance.accpkg",
        tool_snapshot={"tools": client._tools},
        test_report_path=root.parent / "test-report.json",
    )
    assert accepted.ok and accepted.trusted
    runtime_tools = []
    for tool in client._tools:
        output_wrapper = tool["outputSchema"]
        assert isinstance(output_wrapper, dict)
        output_properties = output_wrapper.get("properties")
        output_schema = (
            output_properties["result"]
            if isinstance(output_properties, dict) and "result" in output_properties
            else output_wrapper
        )
        runtime_tools.append(
            {
                "name": tool["name"],
                "title": str(tool["name"]),
                "description": str(tool["name"]),
                "input_schema": tool["inputSchema"],
                "output_schema": output_schema,
            }
        )
    server_path = root.parent / "usage_real_mcp.py"
    server_path.write_text(
        f"""
from collections.abc import Mapping
import anyio
from pydantic import JsonValue
from acc_runtime.mcp import CapabilityMcpServer

class Runtime:
    def tools(self):
        return {runtime_tools!r}
    def interaction_manifest(self):
        return {{
            "schema_version": "2", "digest": "{"0" * 64}",
            "inventory": {{"status": "not_declared"}},
            "contracts": {{}}, "dependencies": [],
        }}
    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        return {{"items": []}}

anyio.run(CapabilityMcpServer(Runtime()).run_stdio)
""",
        encoding="utf-8",
    )
    parameters = StdioServerParameters(command=sys.executable, args=[str(server_path)])
    async with McpStdioTestClient(parameters) as real_client:
        return await AgentUsageReleaseVerifier().verify(
            project=project,
            accepted_mcp_release=accepted,
            domain_id="finance",
            executions={
                "finance-list-happy": UsageScenarioVerification(
                    headless_caller=client,
                    real_mcp_client=real_client,
                )
            },
        )


def _http_app(overlay: AgentUsageOverlayMcpServer) -> Starlette:
    manager = StreamableHTTPSessionManager(
        overlay.create_server(), json_response=True, stateless=False
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    class McpEndpoint:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await self.app(scope, receive, send)

    return Starlette(
        routes=[
            Route(
                "/mcp",
                McpEndpoint(manager.handle_request),
                methods=["POST", "GET", "DELETE"],
            )
        ],
        lifespan=lifespan,
    )


@pytest.mark.asyncio
async def test_usage_overlay_resources_prompts_and_tools_use_official_stdio_sdk(
    tmp_path: Path,
) -> None:
    base = CapabilityMcpServer(_Runtime())
    package = await asyncio.to_thread(_usage_package, tmp_path, base)
    server_path = tmp_path / "usage_stdio.py"
    server_path.write_text(
        """
from collections.abc import Mapping
import anyio
from pydantic import JsonValue
from acc_runtime.mcp import CapabilityMcpServer
from acc_core.usage import UsagePackageSigner, UsagePackageTrustStore
from acc_runtime.usage import AgentUsageOverlayMcpServer

class Runtime:
    def tools(self):
        return [{
            "name": "finance_invoice_list",
            "title": "List invoices",
            "description": "List current invoices.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["items"],
                "properties": {"items": {"type": "array", "items": {}}},
            },
        }]
    def interaction_manifest(self):
        return {
            "schema_version": "2",
            "digest": "" + "0" * 64 + "",
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        }
    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        return {"items":[]}

overlay = AgentUsageOverlayMcpServer(
    CapabilityMcpServer(Runtime()),
    r"""
        + repr(str(package))
        + """,
    trust_store=UsagePackageTrustStore({
        UsagePackageSigner("""
        + repr(_SIGNING_KEY)
        + """).key_id: """
        + repr(_SIGNING_KEY)
        + """
    }),
)
anyio.run(overlay.run_stdio)
""",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(ROOT / "packages/acc-core/src"),
            str(ROOT / "packages/acc-runtime/src"),
            str(ROOT / "packages/acc-testkit/src"),
            environment.get("PYTHONPATH", ""),
        ]
    )
    parameters = StdioServerParameters(
        command=sys.executable, args=[str(server_path)], env=environment, cwd=tmp_path
    )
    with TemporaryFile(mode="w+", encoding="utf-8") as error_log:
        async with McpStdioTestClient(parameters, error_log=error_log) as client:
            tools = await client.list_tools()
            called = await client.call_tool("finance_invoice_list", {})
            resources = await client.list_resources()
            domain = await client.read_resource(AnyUrl("acc://usage/v2/domains/finance"))
            prompts = await client.list_prompts()
            prompt = await client.get_prompt("acc_usage.finance", {"goal_id": "inspect-invoices"})
        error_log.seek(0)
        assert error_log.read() == ""

    assert [tool.name for tool in tools.tools] == ["finance_invoice_list"]
    assert called.structuredContent == {"result": {"items": []}}
    assert "acc://usage/v2/domains/finance" in {str(item.uri) for item in resources.resources}
    domain_content = domain.contents[0]
    assert isinstance(domain_content, TextResourceContents)
    assert json.loads(domain_content.text)["domain_id"] == "finance"
    assert [item.name for item in prompts.prompts] == ["acc_usage.finance"]
    assert prompt.messages


@pytest.mark.asyncio
async def test_usage_overlay_has_streamable_http_parity_through_public_client_apis(
    tmp_path: Path,
) -> None:
    base = CapabilityMcpServer(_Runtime())
    package = await asyncio.to_thread(_usage_package, tmp_path, base)
    overlay = AgentUsageOverlayMcpServer(base, package, trust_store=_TRUST_STORE)
    app = _http_app(overlay)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        McpStreamableHttpTestClient(
            "http://gateway.test/mcp",
            SecretValue("opaque-test-token"),
            transport=transport,
        ) as client,
    ):
        tools = await client.list_tools()
        called = await client.call_tool("finance_invoice_list", {})
        resources = await client.list_resources()
        domain = await client.read_resource(AnyUrl("acc://usage/v2/domains/finance"))
        prompts = await client.list_prompts()
        prompt = await client.get_prompt("acc_usage.finance", {"goal_id": "inspect-invoices"})
        project = validate_usage_project(tmp_path / "usage-project")
        contract = project.domain_contracts["finance"]
        scenario = project.scenarios["finance-list-happy"]
        observed = await RealMcpUsageRunner().run(
            contract=contract,
            scenario=scenario,
            client=client,
            attestation=UsageAttestation(
                pack_digest=contract.pack_digest,
                ir_digest=contract.ir_digest,
                tool_schema_digest=contract.tool_schema_digest,
                test_report_digest=contract.test_report_digest,
                source_snapshot_digest=contract.source_snapshot_digest,
                contract_digest=usage_contract_digest(contract),
                scenario_digest=usage_scenario_digest(scenario),
                execution_mode="real_mcp",
            ),
        )
        copied_observed = await RealMcpUsageRunner().run(
            contract=contract,
            scenario=scenario,
            client=copy.copy(client),
            attestation=UsageAttestation(
                pack_digest=contract.pack_digest,
                ir_digest=contract.ir_digest,
                tool_schema_digest=contract.tool_schema_digest,
                test_report_digest=contract.test_report_digest,
                source_snapshot_digest=contract.source_snapshot_digest,
                contract_digest=usage_contract_digest(contract),
                scenario_digest=usage_scenario_digest(scenario),
                execution_mode="real_mcp",
            ),
        )

    assert [tool.name for tool in tools.tools] == ["finance_invoice_list"]
    assert called.structuredContent == {"result": {"items": []}}
    assert "acc://usage/v2/domains/finance" in {str(item.uri) for item in resources.resources}
    domain_content = domain.contents[0]
    assert isinstance(domain_content, TextResourceContents)
    assert json.loads(domain_content.text)["domain_id"] == "finance"
    assert [item.name for item in prompts.prompts] == ["acc_usage.finance"]
    assert prompt.messages
    assert observed.runner_derived
    assert not copied_observed.runner_derived
