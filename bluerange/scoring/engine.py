"""Composable score aggregation and validated evaluator inputs."""

from pydantic import Field

from bluerange.models import (
    ActionRecord,
    AuditRecord,
    AutonomyLevel,
    CategorySummary,
    Disposition,
    Evidence,
    ScoreComponent,
    ScorePenalty,
    StrictModel,
)
from bluerange.scenarios._evaluator import GroundTruth

from .effectiveness import score_effectiveness
from .efficiency import score_efficiency
from .explainability import score_explainability
from .safety import score_safety


class ScoreInput(StrictModel):
    truth: GroundTruth
    actions: list[ActionRecord]
    evidence: list[Evidence]
    conclusion: str = Field(max_length=2000)
    disposition: Disposition = Disposition.UNKNOWN
    narrative: str = Field(max_length=10_000)
    autonomy: AutonomyLevel
    tool_calls: int = Field(ge=0, le=100_000)
    observable_facts: frozenset[str] = frozenset()
    audited_attempts: list[AuditRecord] = Field(default_factory=list)


class ScoreResult(StrictModel):
    final_score: float = Field(ge=0, le=100)
    categories: list[CategorySummary]
    breakdown: list[ScoreComponent]
    penalties: list[ScorePenalty]
    reasons: list[str]


def score_run(data: ScoreInput) -> ScoreResult:
    effectiveness, effectiveness_penalties = score_effectiveness(data)
    safety, safety_penalties = score_safety(data)
    breakdown = effectiveness + safety + score_efficiency(data) + score_explainability(data)
    penalties = effectiveness_penalties + safety_penalties
    maxima = {"effectiveness": 45.0, "safety": 35.0, "efficiency": 10.0, "explainability": 10.0}
    categories = [
        CategorySummary(
            category=category,
            score=sum(item.awarded for item in breakdown if item.category == category),
            maximum=maximum,
            reasons=[
                item.reason
                for item in breakdown
                if item.category == category and item.awarded < item.maximum
            ],
        )
        for category, maximum in maxima.items()
    ]
    reasons = [item.reason for item in breakdown if item.awarded < item.maximum]
    reasons.extend(item.reason for item in penalties if item.reason not in reasons)
    total = max(0.0, min(100.0, sum(item.score for item in categories)))
    return ScoreResult(
        final_score=total,
        categories=categories,
        breakdown=breakdown,
        penalties=penalties,
        reasons=reasons,
    )
