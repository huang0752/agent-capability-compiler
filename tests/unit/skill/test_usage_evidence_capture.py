from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from acc_core.usage import validate_usage_project
from fs_links import create_link

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-usage-engineer" / "scripts" / "usage_evidence_capture.py"


def _run(*arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, json.loads(completed.stdout)


def _roots(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    source = tmp_path / "source-workspace"
    acc = tmp_path / "acc-project"
    usage = tmp_path / "usage-project"
    source.mkdir()
    acc.mkdir()
    usage.mkdir()
    source_file = source / "frontend" / "pages" / "finance.ts"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("private-source-value\nsecond line\n", encoding="utf-8")
    acceptance = {
        "schema_version": "2",
        "release_id": "mcp-release-1",
        "pack_digest": "sha256:" + "a" * 64,
        "ir_digest": "sha256:" + "b" * 64,
        "tool_schema_digest": "sha256:" + "c" * 64,
        "accepted_domain_ids": ["finance"],
        "test_report_digest": "sha256:" + "d" * 64,
        "known_limitations": [],
        "accepted_by": "user:reviewer",
        "accepted_at": "2026-08-11T00:00:00Z",
    }
    (usage / "mcp-release-acceptance.yaml").write_text(
        yaml.safe_dump(acceptance, sort_keys=False), encoding="utf-8"
    )
    return source, acc, usage, source_file


def _common(source: Path, acc: Path, usage: Path) -> list[str]:
    return [
        "--source-workspace",
        str(source),
        "--acc-project",
        str(acc),
        "--usage-project",
        str(usage),
        "--accepted-mcp-digest",
        "sha256:" + "a" * 64,
        "--domain-id",
        "finance",
        "--source",
        "frontend/pages/finance.ts",
        "--source-id",
        "finance-page",
        "--source-layer",
        "client",
        "--client-surface",
        "web",
        "--output",
        "finance/page.json",
    ]


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def test_capture_requires_accepted_release_and_writes_atomic_locator_only(tmp_path: Path) -> None:
    source, acc, usage, source_file = _roots(tmp_path)
    before = _tree_digest(source)

    completed, payload = _run(*_common(source, acc, usage), "--line-start", "1", "--line-end", "2")

    assert completed.returncode == 0
    assert payload["ok"] is True
    output = usage / "usage-evidence" / "client" / "finance" / "page.json"
    raw = source_file.read_bytes()
    assert json.loads(output.read_text(encoding="utf-8")) == {
        "client_surface": "web",
        "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "domain_id": "finance",
        "kind": "source_file",
        "line_end": 2,
        "line_start": 1,
        "path": "frontend/pages/finance.ts",
        "size_bytes": len(raw),
        "source_layer": "client",
        "source_id": "finance-page",
    }
    assert "private-source-value" not in completed.stdout
    assert "private-source-value" not in output.read_text(encoding="utf-8")
    assert not list(output.parent.glob(".acc-usage-evidence-*"))
    assert _tree_digest(source) == before
    assert list(acc.iterdir()) == []
    report = validate_usage_project(usage)
    assert not any(item.code.startswith("ACC_USAGE_EVIDENCE_") for item in report.diagnostics)


def test_capture_rejects_unaccepted_digest_domain_and_overlapping_roots(tmp_path: Path) -> None:
    source, acc, usage, _ = _roots(tmp_path)
    common = _common(source, acc, usage)

    wrong_digest, wrong_digest_payload = _run(
        *("sha256:" + "e" * 64 if value == "sha256:" + "a" * 64 else value for value in common)
    )
    wrong_domain, wrong_domain_payload = _run(
        *("sales" if value == "finance" else value for value in common)
    )
    overlapping = common.copy()
    overlapping[overlapping.index(str(acc))] = str(source)
    overlap, overlap_payload = _run(*overlapping)

    assert wrong_digest.returncode == 3
    assert wrong_digest_payload["diagnostics"][0]["code"] == "ACC_USAGE_RELEASE_NOT_ACCEPTED"
    assert wrong_domain.returncode == 3
    assert wrong_domain_payload["diagnostics"][0]["code"] == "ACC_USAGE_DOMAIN_NOT_ACCEPTED"
    assert overlap.returncode == 2
    assert overlap_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert not (usage / "usage-evidence").exists()


def test_capture_rejects_traversal_symlink_secret_and_oversize(tmp_path: Path) -> None:
    source, acc, usage, source_file = _roots(tmp_path)
    secret = source / ".env"
    secret.write_text("never-open-production-secret", encoding="utf-8")
    secret.chmod(0)
    linked = source / "linked.ts"
    create_link(linked, source_file)
    common = _common(source, acc, usage)
    source_index = common.index("frontend/pages/finance.ts")

    traversing = common.copy()
    traversing[source_index] = "../outside.ts"
    traversal, traversal_payload = _run(*traversing)
    sensitive = common.copy()
    sensitive[source_index] = ".env"
    secret_result, secret_payload = _run(*sensitive)
    symlinked = common.copy()
    symlinked[source_index] = "linked.ts"
    symlink_result, symlink_payload = _run(*symlinked)
    oversized, oversized_payload = _run(*common, "--max-file-bytes", "4")

    assert traversal.returncode == 2
    assert traversal_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert secret_result.returncode == 3
    assert secret_payload["diagnostics"][0]["code"] == "ACC_SKILL_SECRET_REJECTED"
    assert "never-open-production-secret" not in secret_result.stdout
    assert symlink_result.returncode == 3
    assert symlink_payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"
    assert oversized.returncode == 3
    assert oversized_payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_TOO_LARGE"


def test_capture_cannot_write_outside_fixed_source_layer_directory(tmp_path: Path) -> None:
    source, acc, usage, _ = _roots(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    evidence = usage / "usage-evidence"
    evidence.mkdir()
    create_link(evidence / "client", outside, target_is_directory=True)
    common = _common(source, acc, usage)

    linked, linked_payload = _run(*common)
    traversal = common.copy()
    traversal[traversal.index("finance/page.json")] = "../service/escape.json"
    escaped, escaped_payload = _run(*traversal)

    assert linked.returncode == 3
    assert linked_payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"
    assert escaped.returncode == 2
    assert escaped_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert list(outside.iterdir()) == []


def test_capture_detects_source_mutation_before_atomic_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import importlib.util

    source, acc, usage, source_file = _roots(tmp_path)
    spec = importlib.util.spec_from_file_location("usage_evidence_capture", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original: Callable[[Path, str, Path], Path] = module.safe_output_parent

    def mutate_then_create(root: Path, classification: str, parent: Path) -> Path:
        source_file.write_text("mutated-after-read\n", encoding="utf-8")
        return original(root, classification, parent)

    monkeypatch.setattr(module, "safe_output_parent", mutate_then_create)

    exit_code = module.main(_common(source, acc, usage))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_CHANGED"
    assert not list((usage / "usage-evidence").rglob("*.json"))


@pytest.mark.parametrize(
    ("source_layer", "client_surface"),
    [
        ("client", "mobile"),
        ("service", None),
        ("test", None),
        ("mcp", None),
        ("runtime_observation", None),
    ],
)
def test_capture_supports_each_platform_neutral_source_layer(
    tmp_path: Path, source_layer: str, client_surface: str | None
) -> None:
    source, acc, usage, _ = _roots(tmp_path)
    arguments = _common(source, acc, usage)
    layer_index = arguments.index("client")
    arguments[layer_index] = source_layer
    surface_flag = arguments.index("--client-surface")
    del arguments[surface_flag : surface_flag + 2]
    if client_surface is not None:
        arguments.extend(("--client-surface", client_surface))

    completed, payload = _run(*arguments)

    assert completed.returncode == 0, payload
    output = usage / "usage-evidence" / source_layer / "finance" / "page.json"
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["source_layer"] == source_layer
    assert document.get("client_surface") == client_surface
    assert set(document) <= {
        "client_surface",
        "digest",
        "domain_id",
        "kind",
        "line_end",
        "line_start",
        "path",
        "size_bytes",
        "source_id",
        "source_layer",
    }


def test_capture_rejects_legacy_classification_and_invalid_client_surface(tmp_path: Path) -> None:
    source, acc, usage, _ = _roots(tmp_path)
    common = _common(source, acc, usage)
    legacy = [
        value
        for index, value in enumerate(common)
        if index not in {common.index("--source-layer"), common.index("--source-layer") + 1}
    ]
    legacy.extend(("--classification", "frontend"))
    legacy_result, legacy_payload = _run(*legacy)

    service = common.copy()
    service[service.index("client")] = "service"
    service_result, service_payload = _run(*service)

    assert legacy_result.returncode == 2
    assert legacy_payload["diagnostics"][0]["code"] == "ACC_SKILL_USAGE"
    assert service_result.returncode == 2
    assert service_payload["diagnostics"][0]["code"] == "ACC_SKILL_USAGE"
