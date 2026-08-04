"""Stable, JSON-compatible evaluation results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class EvalDiagnostic:
    """A stable explanation of one failed evaluation assertion."""

    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class CaseResult:
    """Result of checking or running one declared eval case."""

    case_id: str
    capability_id: str
    diagnostics: tuple[EvalDiagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.case_id,
            "capability": self.capability_id,
            "ok": self.ok,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class EvalReport:
    """Deterministically ordered aggregate of contract or runtime eval results."""

    kind: Literal["contract", "runtime"]
    cases: tuple[CaseResult, ...]
    diagnostics: tuple[EvalDiagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.diagnostics and all(case.ok for case in self.cases)

    def to_dict(self) -> dict[str, object]:
        passed = sum(case.ok for case in self.cases)
        return {
            "kind": self.kind,
            "ok": self.ok,
            "summary": {
                "total": len(self.cases),
                "passed": passed,
                "failed": len(self.cases) - passed,
            },
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "cases": [case.to_dict() for case in self.cases],
        }


__all__ = ["CaseResult", "EvalDiagnostic", "EvalReport"]
