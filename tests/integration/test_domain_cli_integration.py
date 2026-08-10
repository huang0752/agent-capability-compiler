from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_domains_status_runs_through_the_installed_cli_entrypoint(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "domain-integration", "version": "2.0.0"},
            "source_workspace": {"path": "../source", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "BASE_URL", "auth": {"kind": "none"}},
            "quality": {"profile": "standard"},
        },
    )
    unknown = {"status": "unknown", "evidence_refs": []}
    _write(
        project / "capability-candidates.yaml",
        {
            "schema_version": "2",
            "candidates": [
                {
                    "id": "orders.search",
                    "domain_id": "orders",
                    "business_intent": "manage_orders",
                    "route_ids": [],
                    "interaction_ids": [],
                    "kind_claim": "read",
                    "effect_claim": "read",
                    "claims": {
                        "schema": unknown,
                        "effect": unknown,
                        "risk": unknown,
                        "reversibility": unknown,
                        "approval": unknown,
                        "retry": unknown,
                        "conflict_control": unknown,
                        "idempotency": unknown,
                        "outcome_resolution": unknown,
                        "lifecycle": unknown,
                        "authorization_boundary": unknown,
                        "identity_binding": unknown,
                        "context_isolation": unknown,
                    },
                    "verification_level": "discovered",
                    "gaps": [],
                }
            ],
        },
    )
    _write(
        project / "domain-map.yaml",
        {
            "schema_version": "2",
            "domains": [
                {
                    "id": "orders",
                    "title": "Orders",
                    "status": "in_progress",
                    "candidate_ids": ["orders.search"],
                    "route_ids": [],
                    "interaction_ids": [],
                    "dependency_domain_ids": [],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                }
            ],
            "unclassified_candidate_ids": [],
            "preferred_order": ["orders"],
        },
    )

    completed = subprocess.run(
        [sys.executable, "-m", "acc_core.cli.main", "domains", "status", str(project), "--json"],
        text=True,
        capture_output=True,
        check=False,
    )
    payload = json.loads(completed.stdout)

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert payload["command"] == "domains status"
    assert payload["result"]["next_domain"] == "orders"
