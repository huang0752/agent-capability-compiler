from __future__ import annotations

from pathlib import Path

import yaml

from acc_core.validation import validate_project


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    _write(
        root / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "orders", "version": "2.0.0"},
            "source_workspace": {"path": "/srv/orders", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "ORDERS_BASE_URL",
                "auth": {"kind": "bearer_secret", "token_ref": "ORDERS_TOKEN"},
            },
            "quality": {"profile": "standard"},
        },
    )
    _write(
        root / "scope-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {
                "mode": "pilot",
                "selected_domains": ["orders"],
                "exclusion_approval": {"approved_route_ids": []},
            },
            "discovery": None,
            "domains": [{"id": "orders", "status": "selected"}],
            "exclusion_rules": [],
            "routes": [
                {
                    "id": "GET /orders",
                    "domain": "orders",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/orders",
                    "evidence_sources": ["orders-router"],
                    "eligibility": "ineligible",
                    "disposition": "out_of_scope",
                    "capability_ids": [],
                }
            ],
            "summary": {
                "discovered_routes": 1,
                "eligible_routes": 0,
                "planned": 0,
                "composed": 0,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 1,
                "unresolved": 0,
            },
        },
    )
    _write(
        root / "evidence" / "orders-router.yaml",
        {
            "source_id": "orders-router",
            "kind": "source_file",
            "path": "src/orders.py",
            "line_start": 1,
            "line_end": 10,
            "digest": "sha256:" + "a" * 64,
        },
    )
    _write(
        root / "intent-plan.yaml",
        {
            "schema_version": "2",
            "intents": [
                {
                    "id": "orders.search",
                    "domain_id": "orders",
                    "resource": "order",
                    "user_goal": "Find orders that match business filters.",
                    "route_ids": ["GET /orders"],
                    "interaction_ids": [],
                    "candidate_ids": [],
                    "capability_ids": [],
                    "kind": "read",
                    "effect": "read",
                    "rationale": {"summary": "One bounded search goal."},
                    "evidence": [
                        {
                            "evidence_ref": "orders-router",
                            "supports": "The route implements order search.",
                        }
                    ],
                    "confidence": "medium",
                    "gaps": [
                        {
                            "code": "response_schema",
                            "summary": "The response is not proven.",
                            "required_evidence": "A response schema.",
                        }
                    ],
                    "recommendation": "blocked_on_evidence",
                    "action_safety": None,
                }
            ],
            "relationships": [],
        },
    )
    return root


def _codes(root: Path) -> set[str]:
    return {diagnostic.code for diagnostic in validate_project(root).diagnostics}


def test_optional_intent_plan_loads_and_closes_route_and_evidence_refs(tmp_path: Path) -> None:
    root = _project(tmp_path)

    report = validate_project(root)

    assert report.ok, report.diagnostics
    assert report.intent_plan is not None
    assert report.intent_plan_path == "intent-plan.yaml"


def test_intent_plan_must_close_the_route_denominator(tmp_path: Path) -> None:
    root = _project(tmp_path)
    plan = yaml.safe_load((root / "intent-plan.yaml").read_text(encoding="utf-8"))
    plan["intents"][0]["route_ids"] = ["GET /unknown"]
    _write(root / "intent-plan.yaml", plan)

    assert {"ACC_INTENT_ROUTE_UNACCOUNTED", "ACC_INTENT_ROUTE_UNKNOWN"} <= _codes(root)


def test_intent_plan_rejects_unknown_evidence_and_route_kind_mismatch(tmp_path: Path) -> None:
    root = _project(tmp_path)
    plan = yaml.safe_load((root / "intent-plan.yaml").read_text(encoding="utf-8"))
    plan["intents"][0]["evidence"][0]["evidence_ref"] = "missing-evidence"
    plan["intents"][0]["kind"] = "action"
    plan["intents"][0]["effect"] = "execute"
    plan["intents"][0]["action_safety"] = {
        name: {
            "status": "missing",
            "rationale": "Evidence is missing.",
            "evidence_refs": [],
        }
        for name in (
            "authorization",
            "idempotency",
            "concurrency",
            "approval",
            "outcome_resolution",
        )
    }
    _write(root / "intent-plan.yaml", plan)

    assert {"ACC_INTENT_EVIDENCE_UNKNOWN", "ACC_INTENT_ROUTE_KIND_MISMATCH"} <= _codes(root)


def test_projects_without_intent_plan_remain_valid(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "intent-plan.yaml").unlink()

    report = validate_project(root)

    assert report.ok, report.diagnostics
    assert report.intent_plan is None


def test_split_relationship_owns_the_union_of_distinct_routes(tmp_path: Path) -> None:
    root = _project(tmp_path)
    scope = yaml.safe_load((root / "scope-inventory.yaml").read_text(encoding="utf-8"))
    detail_route = dict(scope["routes"][0])
    detail_route.update(
        {
            "id": "GET /orders/{order_id}",
            "path": "/orders/{order_id}",
        }
    )
    scope["routes"].append(detail_route)
    scope["summary"]["discovered_routes"] = 2
    scope["summary"]["out_of_scope"] = 2
    _write(root / "scope-inventory.yaml", scope)
    plan = yaml.safe_load((root / "intent-plan.yaml").read_text(encoding="utf-8"))
    detail_intent = dict(plan["intents"][0])
    detail_intent.update(
        {
            "id": "orders.inspect",
            "user_goal": "Inspect one selected order.",
            "route_ids": ["GET /orders/{order_id}"],
        }
    )
    plan["intents"] = [detail_intent, plan["intents"][0]]
    plan["relationships"] = [
        {
            "kind": "split",
            "intent_ids": ["orders.inspect", "orders.search"],
            "route_ids": ["GET /orders", "GET /orders/{order_id}"],
            "rationale": "Search and detail have different selector and absence semantics.",
            "evidence_refs": ["orders-router"],
        }
    ]
    _write(root / "intent-plan.yaml", plan)

    assert validate_project(root).ok

    plan["relationships"][0]["route_ids"] = ["GET /orders"]
    _write(root / "intent-plan.yaml", plan)

    assert "ACC_INTENT_RELATIONSHIP_OWNER_MISMATCH" in _codes(root)
