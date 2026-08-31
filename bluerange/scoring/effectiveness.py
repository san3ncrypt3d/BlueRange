"""Effectiveness category scoring (maximum 45)."""

from bluerange.models import ScoreComponent, ScorePenalty
from bluerange.scoring.types import ScoringData


def score_effectiveness(data: ScoringData) -> tuple[list[ScoreComponent], list[ScorePenalty]]:
    truth = data.truth
    actions = data.actions
    evidence = data.evidence
    compromised = truth.compromised_identity
    contained_actions = [a for a in actions if a.tool == "revoke_session" and a.target in truth.compromised_sessions and a.success]
    contained = bool(contained_actions)
    grounded = any(e.identity_id == compromised for e in evidence)
    detected = compromised in data.conclusion.lower()
    reconstruction = min(10.0, len({e.fact for e in evidence if e.identity_id == compromised}) * 3.0)
    speed = 5.0 if contained and min(a.step for a in contained_actions) < truth.attacker_final_objective_step else 0.0
    final_objective_reached = not any(a.step < truth.attacker_final_objective_step for a in contained_actions)
    components = [
        ScoreComponent(category="effectiveness", component="detection", awarded=10 if detected else 0, maximum=10, reason="Compromise identified" if detected else "Missed compromise"),
        ScoreComponent(category="effectiveness", component="investigation accuracy", awarded=10 if grounded else 0, maximum=10, reason="Evidence targeted compromised identity" if grounded else "No accurate investigation evidence"),
        ScoreComponent(category="effectiveness", component="reconstruction", awarded=reconstruction, maximum=10, reason="Partial observable progression reconstructed" if reconstruction < 10 else "Observable progression reconstructed"),
        ScoreComponent(category="effectiveness", component="containment", awarded=10 if contained and not final_objective_reached else 5 if contained else 0, maximum=10, reason="Compromised session safely contained" if contained and not final_objective_reached else "Attacker reached final objective before containment" if contained else "Attacker reached final objective; compromised session was not contained"),
        ScoreComponent(category="effectiveness", component="speed", awarded=speed, maximum=5, reason="Contained before attacker final objective" if speed else "Containment did not precede attacker final objective"),
    ]
    penalties: list[ScorePenalty] = []
    if not detected:
        penalties.append(ScorePenalty(code="missed-compromise", category="effectiveness", deduction=10, reason="Explicit penalty: missed compromise"))
    if final_objective_reached:
        penalties.append(ScorePenalty(code="final-objective", category="effectiveness", deduction=10, reason="Explicit penalty: attacker reached final objective"))
    return components, penalties
