from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import stat
import struct
import sys
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from mcp.client.stdio import StdioServerParameters

import acc_core.usage.packaging as packaging_module
from acc_core.cli.main import main
from acc_core.packaging import build_pack
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage.acceptance import (
    listed_tool_snapshot_sha256,
    verify_mcp_release_acceptance,
)
from acc_core.usage.models import McpReleaseAcceptance, usage_domain_decision_digest
from acc_core.usage.packaging import (
    USAGE_PACKAGE_FORMAT,
    USAGE_PACKAGE_FORMAT_VERSION,
    UsagePackageBuildResult,
    UsagePackageChecksumMismatchError,
    UsagePackageDuplicateEntryError,
    UsagePackageFileTooLargeError,
    UsagePackageFormatError,
    UsagePackagePathError,
    UsagePackageSigner,
    UsagePackageSymlinkError,
    UsagePackageTrustError,
    UsagePackageTrustStore,
    UsagePackageUnknownEntryError,
    VerifiedUsagePackage,
)
from acc_core.usage.packaging import (
    build_usage_package as _raw_build_usage_package,
)
from acc_core.usage.packaging import (
    verify_usage_package as _raw_verify_usage_package,
)
from acc_core.usage.project import validate_usage_project
from acc_core.usage.verification import VerifiedUsageReleaseBundle
from acc_core.usage.verification_artifact import (
    UsageVerificationArtifactError,
    load_usage_verification_artifact,
    write_usage_verification_artifact,
)
from acc_testkit import McpStdioTestClient
from acc_testkit.usage import (
    AgentUsageReleaseVerifier,
    UsageScenarioVerification,
    UsageToolOutcome,
)
from fs_links import create_link

FIXTURE = Path("tests/fixtures/usage/finance")
_SIGNING_KEY = b"package-test-signing-key-material-32-bytes-minimum"
_SIGNER = UsagePackageSigner(_SIGNING_KEY)
_TRUST_STORE = UsagePackageTrustStore({_SIGNER.key_id: _SIGNING_KEY})


def _digest(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )


class _FixtureMcpClient:
    def __init__(self) -> None:
        self.tools: list[dict[str, object]] = [
            {
                "name": "finance.invoice.list",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                    "required": [],
                },
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "result": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {"items": {"type": "array", "items": {}}},
                            "required": ["items"],
                        }
                    },
                    "required": ["result"],
                },
            }
        ]

    async def list_tools(self) -> list[dict[str, object]]:
        return self.tools

    async def call(self, tool_name: str, arguments: object) -> UsageToolOutcome:
        assert tool_name == "finance.invoice.list"
        assert arguments == {}
        return UsageToolOutcome.success({"items": []})


def _prepare_verified_project(root: Path) -> None:
    client = _FixtureMcpClient()
    interaction = {
        "schema_version": "2",
        "inventory": {"status": "declared"},
        "contracts": {"finance.invoice.list": {}},
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
            "finance.invoice.list": {
                "definition": {
                    "kind": "read",
                    "input_schema": client.tools[0]["inputSchema"],
                    "output_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"items": {"type": "array", "items": {}}},
                        "required": ["items"],
                    },
                }
            }
        },
        "operations": {},
        "policies": {},
        "evals": {},
    }
    pack_project = root.parent / "acc-project"
    pack_project.mkdir(exist_ok=True)
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
    pack_digest = "sha256:" + hashlib.sha256(pack_path.read_bytes()).hexdigest()
    ir_digest = "sha256:" + hashlib.sha256(ir_bytes).hexdigest()
    tool_digest = "sha256:" + listed_tool_snapshot_sha256({"tools": client.tools})
    test_digest = "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
    for relative in (
        "domain-usage-contracts/finance.yaml",
        "domain-index.yaml",
        "mcp-release-acceptance.yaml",
        "releases/finance-1.yaml",
    ):
        path = root / relative
        document = yaml.safe_load(path.read_text())
        document["tool_schema_digest"] = tool_digest
        if "pack_digest" in document:
            document["pack_digest"] = pack_digest
        if "ir_digest" in document:
            document["ir_digest"] = ir_digest
        if "test_report_digest" in document:
            document["test_report_digest"] = test_digest
        path.write_text(yaml.safe_dump(document, sort_keys=False))
    contract_path = root / "domain-usage-contracts/finance.yaml"
    contract = yaml.safe_load(contract_path.read_text())
    contract["tool_routes"][0]["steps"][0]["tool_name"] = "finance.invoice.list"
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
    release_path = root / "releases/finance-1.yaml"
    release = yaml.safe_load(release_path.read_text())
    release["verification"]["host_adapter_verified"] = False
    release["host_adapters"] = []
    release_path.write_text(yaml.safe_dump(release, sort_keys=False))
    decision_path = root / "domain-decisions/finance-1.yaml"
    decision = yaml.safe_load(decision_path.read_text())
    decision["user_confirmation"]["source_text_digest"] = "sha256:" + "f" * 64
    decision_path.write_text(yaml.safe_dump(decision, sort_keys=False))
    _change_contract(root)


async def _build_trusted_bundle(root: Path) -> VerifiedUsageReleaseBundle:
    project = validate_usage_project(root)
    assert project.ok
    acceptance = McpReleaseAcceptance.model_validate(
        yaml.safe_load((root / "mcp-release-acceptance.yaml").read_text())
    ).model_copy(update={"accepted_domain_ids": ["finance"]})
    client = _FixtureMcpClient()
    accepted = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=root.parent / "finance.accpkg",
        tool_snapshot={"tools": client.tools},
        test_report_path=root.parent / "test-report.json",
    )
    assert accepted.ok and accepted.trusted
    output_wrapper = client.tools[0]["outputSchema"]
    assert isinstance(output_wrapper, dict)
    output_properties = output_wrapper["properties"]
    assert isinstance(output_properties, dict)
    output_schema = output_properties["result"]
    server_path = root.parent / "usage_real_mcp.py"
    server_path.write_text(
        f"""
from collections.abc import Mapping
import anyio
from pydantic import JsonValue
from acc_runtime.mcp import CapabilityMcpServer

class Runtime:
    def tools(self):
        return [{{
            "name": "finance.invoice.list",
            "title": "List invoices",
            "description": "List current invoices.",
            "input_schema": {client.tools[0]["inputSchema"]!r},
            "output_schema": {output_schema!r},
        }}]
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


def _trusted_bundle(root: Path) -> VerifiedUsageReleaseBundle:
    return asyncio.run(_build_trusted_bundle(root))


def build_usage_package(root: Path, output: Path) -> UsagePackageBuildResult:
    return _raw_build_usage_package(
        root,
        output,
        verified_releases=(_trusted_bundle(root),),
        signer=_SIGNER,
    )


def verify_usage_package(path: Path, **kwargs: int) -> VerifiedUsagePackage:
    return _raw_verify_usage_package(path, trust_store=_TRUST_STORE, **kwargs)


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "usage-project"
    shutil.copytree(FIXTURE, root)
    _prepare_verified_project(root)
    return root


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def test_signed_usage_verification_artifact_round_trip_and_fail_closed(tmp_path: Path) -> None:
    root = _project(tmp_path)
    report = validate_usage_project(root)
    assert report.ok and report.acceptance is not None
    bundle = _trusted_bundle(root)
    key = b"independent-verification-key-material-32-bytes"
    artifact = tmp_path / "verification.json"
    trust = tmp_path / "trust.json"
    key_id = write_usage_verification_artifact(
        artifact,
        report=report,
        acceptance=report.acceptance,
        bundle=bundle,
        signing_key=key,
        observed_at=100,
        expires_in_seconds=60,
    )
    trust.write_bytes(
        canonical_json_bytes(
            {"schema_version": "2", "keys": {key_id: base64.b64encode(key).decode("ascii")}}
        )
        + b"\n"
    )
    restored = load_usage_verification_artifact(
        artifact,
        trust_store=trust,
        report=report,
        acceptance=report.acceptance,
        domain_id="finance",
        now=120,
    )
    assert restored.trusted

    document = json.loads(artifact.read_bytes())
    document["nonce"] = "0" * 64
    artifact.write_bytes(canonical_json_bytes(document) + b"\n")
    with pytest.raises(UsageVerificationArtifactError, match="invalid, expired"):
        load_usage_verification_artifact(
            artifact,
            trust_store=trust,
            report=report,
            acceptance=report.acceptance,
            domain_id="finance",
            now=120,
        )

    write_usage_verification_artifact(
        artifact,
        report=report,
        acceptance=report.acceptance,
        bundle=bundle,
        signing_key=key,
        observed_at=100,
        expires_in_seconds=1,
    )
    with pytest.raises(UsageVerificationArtifactError, match="invalid, expired"):
        load_usage_verification_artifact(
            artifact,
            trust_store=trust,
            report=report,
            acceptance=report.acceptance,
            domain_id="finance",
            now=120,
        )


def test_usage_verification_artifact_rejects_linked_parent(tmp_path: Path) -> None:
    root = _project(tmp_path)
    report = validate_usage_project(root)
    assert report.ok and report.acceptance is not None
    real = tmp_path / "real-output"
    real.mkdir()
    linked = tmp_path / "linked-output"
    create_link(linked, real, target_is_directory=True)
    with pytest.raises(UsageVerificationArtifactError, match="output path is linked"):
        write_usage_verification_artifact(
            linked / "verification.json",
            report=report,
            acceptance=report.acceptance,
            bundle=_trusted_bundle(root),
            signing_key=b"independent-verification-key-material-32-bytes",
        )


def test_usage_verification_artifact_validity_is_bounded(tmp_path: Path) -> None:
    root = _project(tmp_path)
    report = validate_usage_project(root)
    assert report.ok and report.acceptance is not None
    with pytest.raises(UsageVerificationArtifactError, match="live trusted bundle"):
        write_usage_verification_artifact(
            tmp_path / "too-long.json",
            report=report,
            acceptance=report.acceptance,
            bundle=_trusted_bundle(root),
            signing_key=b"independent-verification-key-material-32-bytes",
            expires_in_seconds=86_401,
        )


def test_usage_cli_release_and_build_require_trusted_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    report = validate_usage_project(root)
    assert report.ok and report.acceptance is not None
    bundle = _trusted_bundle(root)
    key = b"independent-verification-key-material-32-bytes"
    artifact = root / "runner-verification.json"
    trust = tmp_path.parent / f"{tmp_path.name}-independent-trust.json"
    tools = tmp_path / "accepted-tools.json"
    key_id = write_usage_verification_artifact(
        artifact,
        report=report,
        acceptance=report.acceptance,
        bundle=bundle,
        signing_key=key,
    )
    trust.write_bytes(
        canonical_json_bytes(
            {"schema_version": "2", "keys": {key_id: base64.b64encode(key).decode("ascii")}}
        )
        + b"\n"
    )
    tools.write_bytes(canonical_json_bytes({"tools": _FixtureMcpClient().tools}) + b"\n")
    common = [
        "--domain",
        "finance",
        "--project",
        str(root),
        "--verification-artifact",
        str(artifact),
        "--verification-trust-store",
        str(trust),
        "--accepted-pack",
        str(tmp_path / "finance.accpkg"),
        "--accepted-tools",
        str(tools),
        "--accepted-test-report",
        str(tmp_path / "test-report.json"),
        "--json",
    ]
    assert main(["usage", "release", *common, "--check"]) == 0
    monkeypatch.setenv("USAGE_PACKAGE_SECRET", base64.b64encode(_SIGNING_KEY).decode("ascii"))
    assert (
        main(
            [
                "usage",
                "build",
                *common,
                "--output",
                "dist/finance.accusage",
                "--package-signing-secret-env",
                "USAGE_PACKAGE_SECRET",
            ]
        )
        == 0
    )

    document = json.loads(artifact.read_bytes())
    document["nonce"] = "0" * 64
    artifact.write_bytes(canonical_json_bytes(document) + b"\n")
    assert main(["usage", "release", *common, "--check"]) == 3

    write_usage_verification_artifact(
        artifact,
        report=report,
        acceptance=report.acceptance,
        bundle=bundle,
        signing_key=key,
        observed_at=1,
        expires_in_seconds=1,
    )
    assert main(["usage", "release", *common, "--check"]) == 3

    trust_inside = root / "trust.json"
    trust_inside.write_bytes(trust.read_bytes())
    inside = list(common)
    inside[inside.index(str(trust))] = str(trust_inside)
    assert main(["usage", "release", *inside, "--check"]) == 3

    wrong_pack = tmp_path / "wrong.accpkg"
    wrong_pack.write_bytes((tmp_path / "finance.accpkg").read_bytes() + b"\n")
    mismatch = list(common)
    mismatch[mismatch.index(str(tmp_path / "finance.accpkg"))] = str(wrong_pack)
    assert main(["usage", "release", *mismatch, "--check"]) == 3


def _rewrite_archive(
    source: Path,
    destination: Path,
    *,
    add: tuple[str, bytes, int | None] | None = None,
    duplicate: str | None = None,
    replace: tuple[str, bytes] | None = None,
    replacements: dict[str, bytes] | None = None,
) -> None:
    with zipfile.ZipFile(source) as archive:
        members = [(info, archive.read(info)) for info in archive.infolist()]
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        for old_info, contents in members:
            if replace is not None and old_info.filename == replace[0]:
                contents = replace[1]
            if replacements is not None and old_info.filename in replacements:
                contents = replacements[old_info.filename]
            info = zipfile.ZipInfo(old_info.filename, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = old_info.external_attr
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, contents)
            if duplicate == old_info.filename:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(info, contents)
        if add is not None:
            name, contents, mode = add
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = ((stat.S_IFREG | 0o644) if mode is None else mode) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, contents)


def _replace_payload_and_lock(source: Path, destination: Path, path: str, contents: bytes) -> None:
    with zipfile.ZipFile(source) as archive:
        lock = json.loads(archive.read("usage.lock"))
    record = next(item for item in lock["files"] if item["path"] == path)
    record["sha256"] = hashlib.sha256(contents).hexdigest()
    record["size"] = len(contents)
    _rewrite_archive(
        source,
        destination,
        replacements={path: contents, "usage.lock": _canonical(lock)},
    )


def _mark_first_member_encrypted(path: Path) -> None:
    data = bytearray(path.read_bytes())
    local = data.index(b"PK\x03\x04")
    flags = struct.unpack_from("<H", data, local + 6)[0]
    struct.pack_into("<H", data, local + 6, flags | 1)
    central = data.index(b"PK\x01\x02")
    flags = struct.unpack_from("<H", data, central + 8)[0]
    struct.pack_into("<H", data, central + 8, flags | 1)
    path.write_bytes(data)


def _change_contract(root: Path) -> None:
    contract_path = root / "domain-usage-contracts/finance.yaml"
    contract = yaml.safe_load(contract_path.read_text())
    contract["prohibited_behaviors"].append("Do not invent invoice identifiers.")
    contract_path.write_text(yaml.safe_dump(contract, sort_keys=False))
    contract_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )

    decision_path = root / "domain-decisions/finance-1.yaml"
    decision = yaml.safe_load(decision_path.read_text())
    decision["contract_digest"] = contract_digest
    decision["decision_digest"] = usage_domain_decision_digest(decision)
    decision["user_confirmation"]["confirmed_decision_digest"] = decision["decision_digest"]
    decision_path.write_text(yaml.safe_dump(decision, sort_keys=False))

    release_path = root / "releases/finance-1.yaml"
    release = yaml.safe_load(release_path.read_text())
    release["contract_digest"] = contract_digest
    release["decision_digest"] = decision["decision_digest"]
    release_path.write_text(yaml.safe_dump(release, sort_keys=False))


def _add_unselected_route(root: Path) -> None:
    contract_path = root / "domain-usage-contracts/finance.yaml"
    contract = yaml.safe_load(contract_path.read_text())
    contract["business_goals"].append(
        {
            "id": "review-reports-unselected",
            "description": "Review reports that were not selected for this release.",
            "evidence_claim_ids": ["claim-report-goal"],
        }
    )
    contract["tool_routes"].append(
        {
            "id": "report-list-unselected",
            "business_goal_id": "review-reports-unselected",
            "preconditions": [],
            "steps": [
                {
                    "id": "report-list-step-unselected",
                    "capability_id": "finance.invoice.list",
                    "tool_name": "finance.invoice.list",
                    "depends_on_step_ids": [],
                    "binding_ids": [],
                    "condition": None,
                    "retry": "safe",
                    "action_phase": None,
                }
            ],
            "error_branch_ids": ["http-errors-unselected"],
            "result_step_id": "report-list-step-unselected",
            "result_pointer": "/items",
            "action_lifecycle_id": None,
        }
    )
    contract["result_consumption"].append(
        {
            "id": "return-reports-unselected",
            "capability_id": "finance.invoice.list",
            "step_id": "report-list-step-unselected",
            "kind": "return",
            "field_pointers": ["/items"],
            "order": 2,
            "evidence_claim_ids": ["claim-report-result"],
        }
    )
    contract["error_handling"].append(
        {
            "id": "http-errors-unselected",
            "outcomes": ["forbidden", "not_found", "timeout", "unauthorized"],
            "behavior": "stop",
            "description": "Stop on source HTTP failures.",
            "step_ids": ["report-list-step-unselected"],
            "retry_policy": "never",
            "evidence_claim_ids": ["claim-report-result"],
        }
    )
    contract["evidence_claims"][1:1] = [
        {
            "id": "claim-report-goal",
            "statement": "A second valid route exists but was not selected.",
            "target": {
                "target_kind": "business_goal",
                "target_id": "review-reports-unselected",
                "field_pointer": "/description",
            },
            "authority": "observation",
            "source_layer": "client",
            "evidence_refs": [
                {
                    "source_id": "client:finance-screen",
                    "digest": "sha256:" + "4" * 64,
                }
            ],
        },
        {
            "id": "claim-report-result",
            "statement": "The unselected report result would be returned.",
            "target": {
                "target_kind": "result_consumption",
                "target_id": "return-reports-unselected",
                "field_pointer": "/field_pointers",
            },
            "authority": "contract",
            "source_layer": "mcp",
            "evidence_refs": [
                {
                    "source_id": "mcp:finance-invoice-list",
                    "digest": "sha256:" + "5" * 64,
                }
            ],
        },
    ]
    contract_path.write_text(yaml.safe_dump(contract, sort_keys=False))
    _change_contract(root)


def test_build_is_byte_exact_and_contains_only_released_canonical_usage(tmp_path: Path) -> None:
    root = _project(tmp_path)
    first = build_usage_package(root, tmp_path / "first.accusage")
    second = build_usage_package(root, tmp_path / "second.accusage")

    assert first.sha256 == second.sha256
    assert first.path.read_bytes() == second.path.read_bytes()
    assert first.manifest.format == USAGE_PACKAGE_FORMAT == "acc.agent-usage-package"
    assert first.manifest.format_version == USAGE_PACKAGE_FORMAT_VERSION == 2

    verified = verify_usage_package(first.path)
    assert verified.sha256 == first.sha256
    assert verified.manifest == first.manifest
    assert verified.manifest.released_domain_ids == ("finance",)

    with zipfile.ZipFile(first.path) as archive:
        names = archive.namelist()
        contents = b"\n".join(archive.read(name) for name in names)
        for info in archive.infolist():
            assert info.compress_type == zipfile.ZIP_STORED
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.external_attr >> 16 == stat.S_IFREG | 0o644
    assert names == sorted(names)
    assert "manifest.json" in names and "usage.lock" in names
    assert not any(name.endswith(".accpkg") for name in names)
    assert b"../../source-finance" not in contents
    assert b"embedded-artifact:" not in contents
    assert b"Authorization:" not in contents and b"Bearer " not in contents
    assert b'"payload"' not in contents

    manifest = json.loads(zipfile.ZipFile(first.path).read("manifest.json"))
    lock = json.loads(zipfile.ZipFile(first.path).read("usage.lock"))
    assert {item["path"] for item in lock["files"]} == set(names) - {"usage.lock"}
    assert manifest["domains"] == [
        {
            "contract": "domains/0000/contract.json",
            "decision": "domains/0000/decision.json",
            "domain_id": "finance",
            "evidence": "domains/0000/evidence.json",
            "release": "domains/0000/release.json",
            "scenarios": [
                {
                    "path": "domains/0000/scenarios/0000.json",
                    "scenario_id": "finance-list-happy",
                }
            ],
            "usage_release_id": "finance-usage-1",
        }
    ]


def test_changed_contract_changes_package_digest(tmp_path: Path) -> None:
    root = _project(tmp_path)
    before = build_usage_package(root, tmp_path / "before.accusage")
    _change_contract(root)
    after = build_usage_package(root, tmp_path / "after.accusage")
    assert before.sha256 != after.sha256


def test_package_projects_only_the_user_selected_route_closure(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _add_unselected_route(root)

    built = build_usage_package(root, tmp_path / "selected.accusage")
    verified = verify_usage_package(built.path)
    projected = verified.contracts["finance"]

    assert [route.id for route in projected.tool_routes] == ["invoice-list"]
    assert [goal.id for goal in projected.business_goals] == ["inspect-invoices"]
    assert [item.id for item in projected.result_consumption] == ["return-invoices"]
    assert [claim.id for claim in projected.evidence_claims] == ["claim-goal", "claim-result"]
    assert b"unselected" not in built.path.read_bytes()

    full_contract = yaml.safe_load((root / "domain-usage-contracts/finance.yaml").read_text())
    full_contract_bytes = _canonical(full_contract)
    with zipfile.ZipFile(built.path) as archive:
        lock = json.loads(archive.read("usage.lock"))
    contract_record = next(
        item for item in lock["files"] if item["path"] == "domains/0000/contract.json"
    )
    contract_record["sha256"] = hashlib.sha256(full_contract_bytes).hexdigest()
    contract_record["size"] = len(full_contract_bytes)
    tampered = tmp_path / "extra-route.accusage"
    _rewrite_archive(
        built.path,
        tampered,
        replacements={
            "domains/0000/contract.json": full_contract_bytes,
            "usage.lock": _canonical(lock),
        },
    )
    with pytest.raises(UsagePackageFormatError, match="selected route closure"):
        verify_usage_package(tampered)


def test_verified_package_accessors_do_not_expose_mutable_verified_state(
    tmp_path: Path,
) -> None:
    built = build_usage_package(_project(tmp_path), tmp_path / "immutable.accusage")
    verified = verify_usage_package(built.path)
    original_sha256 = verified.sha256

    with pytest.raises((AttributeError, TypeError)):
        cast(Any, verified.contracts).clear()

    contracts = verified.contracts
    releases = verified.releases
    scenarios = verified.scenarios
    contract_snapshot = contracts["finance"]
    contract_snapshot.tool_routes.clear()
    contract_snapshot.business_goals[0].evidence_claim_ids.append("injected")
    release_snapshot = releases["finance"]
    release_snapshot.route_ids.append("injected")
    scenario_snapshot = scenarios["finance-list-happy"]
    scenario_snapshot.expected_outcomes.append("injected")

    assert [route.id for route in contracts["finance"].tool_routes] == ["invoice-list"]
    assert contracts["finance"].business_goals[0].evidence_claim_ids == ["claim-goal"]
    assert releases["finance"].route_ids == ["invoice-list"]
    assert scenarios["finance-list-happy"].expected_outcomes == ["success"]
    assert verified.sha256 == original_sha256
    assert verify_usage_package(built.path).sha256 == original_sha256


def test_verified_package_provenance_rejects_hand_construction_copy_and_field_drift(
    tmp_path: Path,
) -> None:
    verified = verify_usage_package(
        build_usage_package(_project(tmp_path), tmp_path / "provenance.accusage").path
    )
    hand_constructed = VerifiedUsagePackage(
        path=verified.path,
        sha256=verified.sha256,
        manifest=verified.manifest,
        files=verified.files,
        contracts=verified.contracts,
        decisions=verified.decisions,
        releases=verified.releases,
        scenarios=verified.scenarios,
        evidence=verified.evidence,
        release_receipt=verified.release_receipt,
    )
    copied = replace(verified)

    assert not hand_constructed.trusted
    assert not copied.trusted
    object.__setattr__(verified, "sha256", "0" * 64)
    assert not verified.trusted


def test_package_registration_callback_is_not_module_accessible() -> None:
    assert not hasattr(packaging_module, "_register_verified_package")


def test_build_rejects_wrong_suffix_invalid_project_and_symlink_output(tmp_path: Path) -> None:
    root = _project(tmp_path)
    with pytest.raises(UsagePackagePathError):
        build_usage_package(root, tmp_path / "usage.accpkg")

    (root / "scenarios/finance-list-happy.yaml").unlink()
    with pytest.raises(UsagePackageFormatError, match="validation"):
        _raw_build_usage_package(root, tmp_path / "invalid.accusage")

    root = _project(tmp_path / "again")
    target = tmp_path / "target.accusage"
    target.write_bytes(b"existing")
    link = tmp_path / "link.accusage"
    create_link(link, target)
    with pytest.raises(UsagePackageSymlinkError):
        build_usage_package(root, link)


@pytest.mark.parametrize(
    ("name", "error_type"),
    [
        ("unknown.json", UsagePackageUnknownEntryError),
        ("domains/0000/nested/contract.json", UsagePackageUnknownEntryError),
        ("../escape.json", UsagePackagePathError),
        ("C:\\escape.json", UsagePackagePathError),
    ],
)
def test_verify_rejects_unknown_nested_and_traversal_members(
    tmp_path: Path, name: str, error_type: type[Exception]
) -> None:
    built = build_usage_package(_project(tmp_path), tmp_path / "valid.accusage")
    malformed = tmp_path / "malformed.accusage"
    _rewrite_archive(built.path, malformed, add=(name, b"{}\n", None))
    with pytest.raises(error_type):
        verify_usage_package(malformed)


def test_verify_rejects_duplicate_symlink_encrypted_and_oversized_members(tmp_path: Path) -> None:
    built = build_usage_package(_project(tmp_path), tmp_path / "valid.accusage")

    duplicate = tmp_path / "duplicate.accusage"
    _rewrite_archive(built.path, duplicate, duplicate="manifest.json")
    with pytest.raises(UsagePackageDuplicateEntryError):
        verify_usage_package(duplicate)

    symlink = tmp_path / "symlink.accusage"
    _rewrite_archive(
        built.path,
        symlink,
        add=("domains/0001/contract.json", b"target", stat.S_IFLNK | 0o777),
    )
    with pytest.raises(UsagePackageSymlinkError):
        verify_usage_package(symlink)

    encrypted = tmp_path / "encrypted.accusage"
    shutil.copyfile(built.path, encrypted)
    _mark_first_member_encrypted(encrypted)
    with pytest.raises(UsagePackageFormatError, match="encrypted"):
        verify_usage_package(encrypted)

    oversized = tmp_path / "oversized.accusage"
    _rewrite_archive(
        built.path,
        oversized,
        replace=("domains/0000/contract.json", b"x" * (1024 * 1024 + 1)),
    )
    with pytest.raises(UsagePackageFileTooLargeError):
        verify_usage_package(oversized)


def test_verify_rejects_total_limit_and_lock_tampering(tmp_path: Path) -> None:
    built = build_usage_package(_project(tmp_path), tmp_path / "valid.accusage")
    with pytest.raises(UsagePackageFileTooLargeError, match="total"):
        verify_usage_package(built.path, max_total_bytes=100)

    with zipfile.ZipFile(built.path) as archive:
        lock = json.loads(archive.read("usage.lock"))
    lock["files"][0]["sha256"] = "0" * 64
    tampered = tmp_path / "tampered.accusage"
    _rewrite_archive(built.path, tampered, replace=("usage.lock", _canonical(lock)))
    with pytest.raises(UsagePackageChecksumMismatchError):
        verify_usage_package(tampered)


def test_verify_rejects_non_accusage_path(tmp_path: Path) -> None:
    path = tmp_path / "usage.zip"
    path.write_bytes(b"not a package")
    with pytest.raises(UsagePackagePathError):
        verify_usage_package(path)


def test_build_rejects_symlinked_parent(tmp_path: Path) -> None:
    root = _project(tmp_path)
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    create_link(linked_parent, real_parent, target_is_directory=True)
    with pytest.raises(UsagePackageSymlinkError):
        build_usage_package(root, linked_parent / "usage.accusage")


def test_atomic_replace_does_not_leave_temporary_files(tmp_path: Path) -> None:
    root = _project(tmp_path)
    output = tmp_path / "usage.accusage"
    build_usage_package(root, output)
    first_inode = os.stat(output).st_ino
    build_usage_package(root, output)
    assert os.stat(output).st_ino != first_inode
    assert not list(tmp_path.glob(".usage.accusage.*.tmp"))


def test_published_build_requires_exact_live_bundle_and_signer(tmp_path: Path) -> None:
    root = _project(tmp_path)
    live = _trusted_bundle(root)
    serialized = VerifiedUsageReleaseBundle.model_validate_json(live.model_dump_json())

    with pytest.raises(UsagePackageTrustError, match="verified release bundle"):
        _raw_build_usage_package(root, tmp_path / "missing-bundle.accusage")
    with pytest.raises(UsagePackageTrustError, match="live"):
        _raw_build_usage_package(
            root,
            tmp_path / "serialized-bundle.accusage",
            verified_releases=(serialized,),
            signer=_SIGNER,
        )
    with pytest.raises(UsagePackageTrustError, match="signer"):
        _raw_build_usage_package(
            root,
            tmp_path / "missing-signer.accusage",
            verified_releases=(live,),
        )


def test_signed_receipt_is_required_and_verified_by_explicit_trust_root(
    tmp_path: Path,
) -> None:
    built = build_usage_package(_project(tmp_path), tmp_path / "signed.accusage")
    with zipfile.ZipFile(built.path) as archive:
        assert "release-receipt.json" in archive.namelist()
        receipt = json.loads(archive.read("release-receipt.json"))
    assert receipt["algorithm"] == "hmac-sha256"
    assert receipt["key_id"] == _SIGNER.key_id
    assert receipt["domains"][0]["domain_id"] == "finance"

    verified = _raw_verify_usage_package(built.path, trust_store=_TRUST_STORE)
    assert verified.trusted
    assert verified.release_receipt is not None
    assert verified.release_receipt.key_id == _SIGNER.key_id

    with pytest.raises(UsagePackageTrustError, match="trust store"):
        _raw_verify_usage_package(built.path)
    wrong_key = b"wrong-deployment-trust-root-material-32-bytes"
    wrong_signer = UsagePackageSigner(wrong_key)
    wrong_store = UsagePackageTrustStore({wrong_signer.key_id: wrong_key})
    with pytest.raises(UsagePackageTrustError, match="signature"):
        _raw_verify_usage_package(built.path, trust_store=wrong_store)


def test_receipt_tampering_fails_even_when_lock_is_recomputed(tmp_path: Path) -> None:
    built = build_usage_package(_project(tmp_path), tmp_path / "signed.accusage")
    with zipfile.ZipFile(built.path) as archive:
        receipt = json.loads(archive.read("release-receipt.json"))
    receipt["signature"] = "0" * 64
    tampered = tmp_path / "tampered-receipt.accusage"
    _replace_payload_and_lock(built.path, tampered, "release-receipt.json", _canonical(receipt))
    with pytest.raises(UsagePackageTrustError, match="signature"):
        verify_usage_package(tampered)


def test_limited_empty_package_is_structurally_valid_but_untrusted(tmp_path: Path) -> None:
    root = tmp_path / "mobile"
    shutil.copytree(Path("tests/fixtures/usage/mobile"), root)
    built = _raw_build_usage_package(root, tmp_path / "limited.accusage")
    verified = _raw_verify_usage_package(built.path)

    assert verified.manifest.released_domain_ids == ()
    assert not verified.trusted
    assert verified.release_receipt is None
    with zipfile.ZipFile(built.path) as archive:
        assert "release-receipt.json" not in archive.namelist()


def test_signing_roots_are_copied_and_never_exposed_in_repr_or_errors() -> None:
    secret = bytearray(b"secret-sentinel-deployment-root-32-bytes")
    signer = UsagePackageSigner(bytes(secret))
    key_id = signer.key_id
    store = UsagePackageTrustStore([(key_id, bytes(secret))])
    secret[:] = b"x" * len(secret)

    assert "secret-sentinel" not in repr(signer)
    assert "secret-sentinel" not in repr(store)
    with pytest.raises(ValueError) as short:
        UsagePackageSigner(b"secret-sentinel")
    assert "secret-sentinel" not in str(short.value)
    with pytest.raises(ValueError, match="duplicated") as duplicate:
        UsagePackageTrustStore([(key_id, b"secret-sentinel-deployment-root-32-bytes")] * 2)
    assert "secret-sentinel" not in str(duplicate.value)
