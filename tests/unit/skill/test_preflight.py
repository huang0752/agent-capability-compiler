from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "preflight.py"


def _run(*arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, json.loads(completed.stdout)


def test_preflight_reports_safe_read_only_workspace_hints_without_writing(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    project = tmp_path / "project"
    source.mkdir()
    project.mkdir()
    (source / "openapi.json").write_text("{}", encoding="utf-8")
    (source / "tests").mkdir()
    (source / "tests" / "test_api.py").write_text("def test_api(): pass\n", encoding="utf-8")
    before = sorted(path.relative_to(source).as_posix() for path in source.rglob("*"))

    completed, payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--acc-command",
        sys.executable,
    )

    assert completed.returncode == 0
    assert payload["ok"] is True
    result = payload["result"]
    assert result["source_mode"] == "read_only"
    assert result["acc_available"] is True
    assert result["openapi_candidates"] == ["openapi.json"]
    assert result["test_candidates"] == ["tests/test_api.py"]
    assert result["suggested_test_commands"] == ["pytest"]
    assert sorted(path.relative_to(source).as_posix() for path in source.rglob("*")) == before


def test_preflight_stops_on_secret_and_symlink_without_reading_targets(tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = tmp_path / "project"
    source.mkdir()
    project.mkdir()
    secret = "production-secret-never-output"
    sensitive = source / ".env.production"
    sensitive.write_text(secret, encoding="utf-8")
    sensitive.chmod(0)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside-secret-never-output", encoding="utf-8")
    (source / "linked.txt").symlink_to(outside)

    completed, payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--acc-command",
        sys.executable,
    )

    assert completed.returncode == 3
    assert payload["ok"] is False
    assert [item["code"] for item in payload["diagnostics"]] == [
        "ACC_SKILL_SECRET_FILE_DETECTED",
        "ACC_SKILL_SYMLINK_REJECTED",
    ]
    assert secret not in completed.stdout
    assert "outside-secret-never-output" not in completed.stdout


def test_preflight_rejects_overlap_missing_acc_and_oversized_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    nested_project = source / "project"
    nested_project.mkdir()
    sibling_project = tmp_path / "sibling-project"
    sibling_project.mkdir()
    (source / "large.bin").write_bytes(b"12345")

    overlap, overlap_payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(nested_project),
        "--acc-command",
        sys.executable,
    )
    missing, missing_payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(sibling_project),
        "--acc-command",
        "definitely-missing-acc-command",
        "--max-file-bytes",
        "4",
    )

    assert overlap.returncode == 2
    assert overlap_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert missing.returncode == 3
    assert [item["code"] for item in missing_payload["diagnostics"]] == [
        "ACC_SKILL_ACC_NOT_FOUND",
        "ACC_SKILL_FILE_TOO_LARGE",
    ]
