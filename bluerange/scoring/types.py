"""Typed input protocol shared by independent scoring components."""

from typing import Protocol

from bluerange.models import ActionRecord, AuditRecord, AutonomyLevel, Evidence
from bluerange.scenarios import GroundTruth


class ScoringData(Protocol):
    truth: GroundTruth
    actions: list[ActionRecord]
    evidence: list[Evidence]
    conclusion: str
    narrative: str
    autonomy: AutonomyLevel
    tool_calls: int
    observable_facts: frozenset[str]
    audited_attempts: list[AuditRecord]
