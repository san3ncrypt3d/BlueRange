"""Typed input protocol shared by independent scoring components."""

from typing import Protocol

from bluerange.models import ActionRecord, AuditRecord, AutonomyLevel, Disposition, Evidence
from bluerange.scenarios._evaluator import GroundTruth


class ScoringData(Protocol):
    truth: GroundTruth
    actions: list[ActionRecord]
    evidence: list[Evidence]
    conclusion: str
    disposition: Disposition
    narrative: str
    autonomy: AutonomyLevel
    tool_calls: int
    observable_facts: frozenset[str]
    audited_attempts: list[AuditRecord]
