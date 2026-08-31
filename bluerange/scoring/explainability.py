"""Explainability category scoring (maximum 10)."""

from bluerange.models import ScoreComponent
from bluerange.scoring.types import ScoringData


def score_explainability(data: ScoringData) -> list[ScoreComponent]:
    grounded = any(e.identity_id == data.truth.compromised_identity for e in data.evidence)
    narrative = data.narrative
    narrative_score = 3 if narrative else 0
    return [
        ScoreComponent(category="explainability", component="evidence-backed conclusion", awarded=5 if grounded and data.conclusion else 0, maximum=5, reason="Conclusion supported by observed identity evidence" if grounded and data.conclusion else "Conclusion lacks evidence"),
        ScoreComponent(category="explainability", component="incident narrative", awarded=narrative_score, maximum=5, reason="Concise narrative supplied; complete reconstruction and escalation rationale absent" if narrative else "No incident narrative"),
    ]
