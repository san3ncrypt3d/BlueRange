"""Explainability category scoring (maximum 10)."""

from bluerange.models import ScoreComponent
from bluerange.scoring.types import ScoringData


def score_explainability(data: ScoringData) -> list[ScoreComponent]:
    grounded = bool(
        [
            e
            for e in data.evidence
            if (
                data.truth.compromised_identity is None
                or e.identity_id == data.truth.compromised_identity
            )
            and (not data.observable_facts or e.fact in data.observable_facts)
        ]
    )
    narrative = data.narrative
    narrative_score = 3 if narrative and grounded and data.conclusion else 0
    return [
        ScoreComponent(
            category="explainability",
            component="evidence-backed conclusion",
            awarded=5 if grounded and data.conclusion else 0,
            maximum=5,
            reason="Conclusion supported by observed identity evidence"
            if grounded and data.conclusion
            else "Conclusion lacks evidence",
        ),
        ScoreComponent(
            category="explainability",
            component="incident narrative",
            awarded=narrative_score,
            maximum=5,
            reason="Concise narrative supplied; complete reconstruction and escalation rationale absent"
            if narrative
            else "No incident narrative",
        ),
    ]
