from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from fs_links import create_link

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "artifact_manifest.py"


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "acc-project"
    (project / "capabilities").mkdir(parents=True)
    (project / "project.yaml").write_text("id: example\n", encoding="utf-8")
    (project / "capabilities" / "read.yaml").write_text("id: read_example\n", encoding="utf-8")
    return project


def _run(project: Path, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--project", str(project), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    payload = json.loads(completed.stdout) if completed.stdout else {}
    return completed, payload


def test_manifest_is_deterministic_sorted_and_excludes_its_output(tmp_path: Path) -> None:
    project = _project(tmp_path)

    first, first_payload = _run(project, "--output", "artifact-manifest.json")
    second, second_payload = _run(project, "--output", "artifact-manifest.json")

    assert first.returncode == second.returncode == 0
    assert first_payload["result"]["files"] == second_payload["result"]["files"]
    assert first_payload["result"]["digest"] == second_payload["result"]["digest"]
    assert [item["path"] for item in first_payload["result"]["files"]] == [
        "capabilities/read.yaml",
        "project.yaml",
    ]
    assert (
        json.loads((project / "artifact-manifest.json").read_text(encoding="utf-8"))
        == (second_payload["result"])
    )


def test_manifest_rejects_symlinks_without_reading_the_target(tmp_path: Path) -> None:
    project = _project(tmp_path)
    secret = "outside-secret-never-output"
    outside = tmp_path / "outside.txt"
    outside.write_text(secret, encoding="utf-8")
    create_link(project / "linked.txt", outside)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"
    assert secret not in completed.stdout


def test_manifest_rejects_sensitive_files_without_reading_them(tmp_path: Path) -> None:
    project = _project(tmp_path)
    secret = "production-token-never-output"
    sensitive = project / ".env.production"
    sensitive.write_text(secret, encoding="utf-8")
    sensitive.chmod(0)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_SECRET_REJECTED"
    assert secret not in completed.stdout


def test_manifest_rejects_output_outside_the_project(tmp_path: Path) -> None:
    project = _project(tmp_path)

    completed, payload = _run(project, "--output", str(tmp_path / "outside.json"))

    assert completed.returncode == 2
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert not (tmp_path / "outside.json").exists()


def test_manifest_rejects_oversized_files_without_outputting_content(tmp_path: Path) -> None:
    project = _project(tmp_path)
    secret = "oversized-secret-never-output"
    (project / "large.txt").write_text(secret, encoding="utf-8")

    completed, payload = _run(project, "--max-file-bytes", "8")

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_TOO_LARGE"
    assert secret not in completed.stdout


def test_manifest_rejects_nested_source_workspaces(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "source" / ".git").mkdir(parents=True)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_NESTED_WORKSPACE_REJECTED"
