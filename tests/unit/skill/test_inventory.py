from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "inventory.py"


def _run(*arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, json.loads(completed.stdout)


def test_inventory_is_sorted_and_never_reads_or_outputs_secret_files(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    (workspace / "z.py").write_text("print('safe')\n", encoding="utf-8")
    (workspace / "openapi.json").write_text("{}", encoding="utf-8")
    secret = "production-token-never-output"
    (workspace / ".env.production").write_text(secret, encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside-secret-never-output", encoding="utf-8")
    (workspace / "linked.txt").symlink_to(outside)

    completed, payload = _run("--workspace", str(workspace))

    assert completed.returncode == 0
    assert payload["ok"] is True
    result = payload["result"]
    assert [item["path"] for item in result["files"]] == ["openapi.json", "z.py"]
    assert result["sensitive_paths"] == [".env.production"]
    assert result["symlinks"] == ["linked.txt"]
    assert result["openapi_candidates"] == ["openapi.json"]
    assert secret not in completed.stdout
    assert "outside-secret-never-output" not in completed.stdout


def test_inventory_fails_closed_on_oversized_regular_files(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    workspace.mkdir()
    (workspace / "large.bin").write_bytes(b"x" * 100)

    completed, payload = _run("--workspace", str(workspace), "--max-file-bytes", "4")

    assert completed.returncode == 3
    assert payload["ok"] is False
    assert payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_TOO_LARGE"
    assert "12345" not in completed.stdout


def test_inventory_limits_hashing_to_explicit_include_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    selected = workspace / "backend" / "app"
    selected.mkdir(parents=True)
    (selected / "routes.py").write_text("router = object()\n", encoding="utf-8")
    (workspace / ".env").write_text("must-not-be-read", encoding="utf-8")
    (workspace / "large.bin").write_bytes(b"x" * 100)

    completed, payload = _run(
        "--workspace",
        str(workspace),
        "--max-file-bytes",
        "64",
        "--include",
        "backend/app/routes.py",
    )

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["include_paths"] == ["backend/app/routes.py"]
    assert [item["path"] for item in payload["result"]["files"]] == [
        "backend/app/routes.py"
    ]
    assert payload["result"]["sensitive_paths"] == []
    assert "must-not-be-read" not in completed.stdout
