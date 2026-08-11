from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sys
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml
from mcp import types
from mcp.client.stdio import StdioServerParameters
from pydantic import AnyUrl, JsonValue

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
from acc_runtime.mcp import CapabilityMcpServer
from acc_runtime.usage import (
    AgentUsageOverlayMcpServer,
    UsageOverlayDigestMismatchError,
    UsageOverlayError,
    UsageOverlayTrustError,
)
from acc_testkit import McpStdioTestClient
from acc_testkit.usage import (
    AgentUsageReleaseVerifier,
    UsageScenarioVerification,
    UsageToolOutcome,
)

_SIGNING_KEY = b"overlay-test-signing-root-material-32-bytes"
_SIGNER = UsagePackageSigner(_SIGNING_KEY)
_TRUST_STORE = UsagePackageTrustStore({_SIGNER.key_id: _SIGNING_KEY})


class _Runtime:
    calls: list[tuple[str, dict[str, object]]]

    def __init__(self) -> None:
        self.calls = []
        self.added_tool = False

    def tools(self) -> list[dict[str, object]]:
        tools: list[dict[str, object]] = [
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
        if self.added_tool:
            tools.append(
                {
                    "name": "finance_invoice_get",
                    "title": "Get invoice",
                    "description": "Get one invoice.",
                    "input_schema": {"type": "object", "properties": {}},
                    "output_schema": {"type": "object", "properties": {}},
                }
            )
        return tools

    def interaction_manifest(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "2",
            "digest": "0" * 64,
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        }

    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue:
        self.calls.append((capability_id, dict(arguments)))
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


@pytest.mark.asyncio
async def test_overlay_delegates_tools_and_exposes_only_released_canonical_usage(
    tmp_path: Path,
) -> None:
    runtime = _Runtime()
    base = CapabilityMcpServer(runtime)
    package = await asyncio.to_thread(_usage_package, tmp_path, base)
    overlay = AgentUsageOverlayMcpServer(base, package, trust_store=_TRUST_STORE)

    assert overlay.list_tools() == base.list_tools()
    result = await overlay.call_tool("finance_invoice_list", {})
    assert result.structuredContent == {"result": {"items": []}}
    assert runtime.calls == [("finance_invoice_list", {})]

    usage_resources = [
        resource
        for resource in overlay.list_resources()
        if str(resource.uri).startswith("acc://usage/v2/")
    ]
    assert [str(resource.uri) for resource in usage_resources] == [
        "acc://usage/v2/manifest",
        "acc://usage/v2/domains/finance",
    ]
    contents = overlay.read_resource(AnyUrl("acc://usage/v2/domains/finance"))
    assert len(contents) == 1
    raw = str(contents[0].content)
    assert (
        raw
        == json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    assert "client:finance-screen" not in raw
    assert "evidence_claim" not in raw
    payload = json.loads(raw)
    assert payload["domain_id"] == "finance"
    assert [goal["id"] for goal in payload["business_goals"]] == ["inspect-invoices"]
    assert [route["id"] for route in payload["tool_routes"]] == ["invoice-list"]


def test_overlay_generates_bounded_secret_free_prompt_and_fails_closed(
    tmp_path: Path,
) -> None:
    base = CapabilityMcpServer(_Runtime())
    package = _usage_package(tmp_path, base)
    overlay = AgentUsageOverlayMcpServer(base, package, trust_store=_TRUST_STORE)

    prompts = overlay.list_prompts()
    assert [prompt.name for prompt in prompts] == ["acc_usage.finance"]
    assert [(argument.name, argument.required) for argument in prompts[0].arguments or []] == [
        ("goal_id", True)
    ]
    prompt = overlay.get_prompt("acc_usage.finance", {"goal_id": "inspect-invoices"})
    assert len(prompt.messages) == 1
    content = prompt.messages[0].content
    assert isinstance(content, types.TextContent)
    assert len(content.text.encode()) <= 32 * 1024
    assert "Authorization" not in content.text and "Bearer " not in content.text

    with pytest.raises(ValueError, match="unknown or invalid prompt request"):
        overlay.get_prompt("acc_usage.finance", {"goal_id": "Bearer private-value"})
    with pytest.raises(ValueError, match="unknown Usage resource"):
        overlay.read_resource("acc://usage/v2/domains/not-released")

    stale_parent = tmp_path / "stale"
    stale_parent.mkdir()
    stale_runtime = _Runtime()
    stale_runtime.added_tool = True
    stale_base = CapabilityMcpServer(stale_runtime)
    stale = _usage_package(stale_parent, stale_base)
    with pytest.raises(UsageOverlayDigestMismatchError):
        AgentUsageOverlayMcpServer(base, stale, trust_store=_TRUST_STORE)


@pytest.mark.asyncio
async def test_overlay_fails_closed_if_delegated_tool_digest_drifts_after_load(
    tmp_path: Path,
) -> None:
    runtime = _Runtime()
    base = CapabilityMcpServer(runtime)
    package = await asyncio.to_thread(_usage_package, tmp_path, base)
    overlay = AgentUsageOverlayMcpServer(base, package, trust_store=_TRUST_STORE)
    runtime.added_tool = True

    with pytest.raises(UsageOverlayDigestMismatchError):
        overlay.list_tools()
    with pytest.raises(UsageOverlayDigestMismatchError):
        overlay.read_resource("acc://usage/v2/domains/finance")
    with pytest.raises(UsageOverlayDigestMismatchError):
        overlay.get_prompt("acc_usage.finance", {"goal_id": "inspect-invoices"})
    with pytest.raises(UsageOverlayDigestMismatchError):
        await overlay.call_tool("finance_invoice_list", {})
    assert runtime.calls == []


@pytest.mark.asyncio
async def test_overlay_fails_closed_if_usage_package_bytes_drift_after_load(
    tmp_path: Path,
) -> None:
    runtime = _Runtime()
    base = CapabilityMcpServer(runtime)
    package = await asyncio.to_thread(_usage_package, tmp_path, base)
    overlay = AgentUsageOverlayMcpServer(base, package, trust_store=_TRUST_STORE)
    package.write_bytes(b"untrusted replacement with secret-sentinel")

    operations = (
        overlay.list_tools,
        overlay.list_resources,
        lambda: overlay.read_resource("acc://usage/v2/domains/finance"),
        overlay.list_prompts,
        lambda: overlay.get_prompt("acc_usage.finance", {"goal_id": "inspect-invoices"}),
    )
    for operation in operations:
        with pytest.raises(UsageOverlayTrustError) as caught:
            operation()
        assert "secret-sentinel" not in str(caught.value)
        assert str(package) not in str(caught.value)

    with pytest.raises(UsageOverlayTrustError) as caught:
        await overlay.call_tool("finance_invoice_list", {})
    assert "secret-sentinel" not in str(caught.value)
    assert str(package) not in str(caught.value)
    assert runtime.calls == []


def test_overlay_requires_explicit_trust_and_rejects_wrong_missing_or_empty_receipts(
    tmp_path: Path,
) -> None:
    base = CapabilityMcpServer(_Runtime())
    signed = _usage_package(tmp_path, base)

    with pytest.raises(UsageOverlayError):
        AgentUsageOverlayMcpServer(base, signed)

    wrong_key = b"overlay-wrong-signing-root-material-32-bytes"
    wrong_signer = UsagePackageSigner(wrong_key)
    wrong_store = UsagePackageTrustStore({wrong_signer.key_id: wrong_key})
    with pytest.raises(UsageOverlayError):
        AgentUsageOverlayMcpServer(base, signed, trust_store=wrong_store)

    missing = tmp_path / "missing-receipt.accusage"
    with zipfile.ZipFile(signed) as source, zipfile.ZipFile(missing, "w") as destination:
        for info in source.infolist():
            if info.filename != "release-receipt.json":
                destination.writestr(info, source.read(info))
    with pytest.raises(UsageOverlayError):
        AgentUsageOverlayMcpServer(base, missing, trust_store=_TRUST_STORE)

    empty_root = tmp_path / "empty"
    shutil.copytree(Path("tests/fixtures/usage/mobile"), empty_root)
    empty = tmp_path / "empty.accusage"
    build_usage_package(empty_root, empty)
    with pytest.raises(UsageOverlayError):
        AgentUsageOverlayMcpServer(base, empty, trust_store=UsagePackageTrustStore({}))
