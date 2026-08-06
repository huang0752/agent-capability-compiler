from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "verify_read_only_workspace.py"


def _run(*arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, json.loads(completed.stdout)


def test_diagnostic_optionally_includes_a_json_pointer() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_read_only_workspace", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.diagnostic("ACC_SCOPE_INVALID", "invalid", path="scope.yaml") == {
        "code": "ACC_SCOPE_INVALID",
        "severity": "error",
        "message": "invalid",
        "path": "scope.yaml",
    }
    assert module.diagnostic(
        "ACC_SCOPE_INVALID",
        "invalid",
        path="scope.yaml",
        pointer="/routes/0/disposition",
    )["pointer"] == "/routes/0/disposition"


def test_verify_snapshots_regular_files_without_following_symlinks(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    (workspace / "a.txt").write_text("alpha", encoding="utf-8")
    (workspace / "nested").mkdir()
    (workspace / "nested" / "b.txt").write_text("beta", encoding="utf-8")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("never-read-this-secret", encoding="utf-8")
    (workspace / "linked.txt").symlink_to(outside)

    completed, payload = _run("--workspace", str(workspace))

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["command"] == "verify-read-only-workspace"
    assert [item["path"] for item in payload["result"]["snapshot"]["files"]] == [
        "a.txt",
        "nested/b.txt",
    ]
    assert payload["result"]["snapshot"]["symlinks"] == ["linked.txt"]
    assert "never-read-this-secret" not in completed.stdout


def test_verify_compares_a_previous_snapshot_without_writing_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    source = workspace / "module.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _, first = _run("--workspace", str(workspace))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(first), encoding="utf-8")

    unchanged, unchanged_payload = _run("--workspace", str(workspace), "--baseline", str(baseline))
    source.write_text("value = 2\n", encoding="utf-8")
    changed, changed_payload = _run("--workspace", str(workspace), "--baseline", str(baseline))

    assert unchanged.returncode == 0
    assert unchanged_payload["result"]["unchanged"] is True
    assert changed.returncode == 3
    assert changed_payload["ok"] is False
    assert changed_payload["result"]["unchanged"] is False
    assert changed_payload["diagnostics"][0]["code"] == "ACC_SKILL_WORKSPACE_CHANGED"


def test_verify_rejects_parent_segments_and_oversized_files(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    (workspace / "large.txt").write_bytes(b"12345")

    traversing, traversing_payload = _run("--workspace", str(workspace / ".." / "source"))
    oversized, oversized_payload = _run("--workspace", str(workspace), "--max-file-bytes", "4")

    assert traversing.returncode == 2
    assert traversing_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert oversized.returncode == 3
    assert oversized_payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_TOO_LARGE"


def test_verify_argparse_errors_are_json(tmp_path: Path) -> None:
    completed, payload = _run("--workspace", str(tmp_path), "--max-file-bytes", "0")

    assert completed.returncode == 2
    assert payload["ok"] is False
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_USAGE"
    assert completed.stderr == ""


def test_verify_never_opens_sensitive_named_files(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    sensitive = workspace / ".env"
    secret = "production-secret-never-output"
    sensitive.write_text(secret, encoding="utf-8")
    sensitive.chmod(0)

    completed, payload = _run("--workspace", str(workspace))

    assert completed.returncode == 0
    assert payload["result"]["snapshot"]["files"] == []
    assert payload["result"]["snapshot"]["sensitive_paths"] == [
        {"path": ".env", "size": len(secret)}
    ]
    assert secret not in completed.stdout


def test_verify_never_opens_sensitive_named_baselines(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    baseline = tmp_path / ".env"
    secret = "baseline-secret-never-output"
    baseline.write_text(secret, encoding="utf-8")
    baseline.chmod(0)

    completed, payload = _run("--workspace", str(workspace), "--baseline", str(baseline))

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_SECRET_REJECTED"
    assert secret not in completed.stdout


def test_verify_scoped_snapshot_ignores_changes_outside_include_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    selected = workspace / "backend" / "app"
    selected.mkdir(parents=True)
    route = selected / "routes.py"
    route.write_text("value = 1\n", encoding="utf-8")
    outside = workspace / "large.bin"
    outside.write_bytes(b"x" * 4096)

    _, first = _run(
        "--workspace",
        str(workspace),
        "--max-file-bytes",
        "2048",
        "--include",
        "backend/app/routes.py",
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(first), encoding="utf-8")
    outside.write_bytes(b"changed-outside-scope")

    unchanged, unchanged_payload = _run(
        "--workspace",
        str(workspace),
        "--baseline",
        str(baseline),
        "--max-file-bytes",
        "2048",
        "--include",
        "backend/app/routes.py",
    )
    route.write_text("value = 2\n", encoding="utf-8")
    changed, changed_payload = _run(
        "--workspace",
        str(workspace),
        "--baseline",
        str(baseline),
        "--max-file-bytes",
        "2048",
        "--include",
        "backend/app/routes.py",
    )

    assert unchanged.returncode == 0
    assert unchanged_payload["result"]["unchanged"] is True
    assert unchanged_payload["result"]["snapshot"]["include_paths"] == [
        "backend/app/routes.py"
    ]
    assert changed.returncode == 3
    assert changed_payload["diagnostics"][0]["code"] == "ACC_SKILL_WORKSPACE_CHANGED"
