"""Efficiency category scoring (maximum 10)."""

from bluerange.models import ScoreComponent
from bluerange.scoring.types import ScoringData


def score_efficiency(data: ScoringData) -> list[ScoreComponent]:
    calls = data.tool_calls
    return [
        ScoreComponent(category="efficiency", component="calls", awarded=4 if calls <= 8 else 2, maximum=4, reason=f"{calls} tool calls"),
        ScoreComponent(category="efficiency", component="model cost", awarded=3, maximum=3, reason="No metered model cost"),
        ScoreComponent(category="efficiency", component="latency", awarded=3, maximum=3, reason="In-memory execution"),
    ]
