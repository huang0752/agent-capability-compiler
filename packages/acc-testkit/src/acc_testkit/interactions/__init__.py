"""Headless interaction-contract conformance utilities."""

from acc_testkit.interactions.evaluator import (
    HeadlessInteractionEvaluator,
    InteractionEvaluationError,
    evaluate_condition,
)
from acc_testkit.interactions.models import (
    ClientAdapterConformanceReport,
    ClientAdapterConformanceStep,
    InteractionTraceEntry,
)

__all__ = [
    "ClientAdapterConformanceReport",
    "ClientAdapterConformanceStep",
    "HeadlessInteractionEvaluator",
    "InteractionEvaluationError",
    "InteractionTraceEntry",
    "evaluate_condition",
]
