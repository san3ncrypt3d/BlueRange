"""Effectiveness category scoring (maximum 45)."""

from bluerange.models import Disposition, ScoreComponent, ScorePenalty
from bluerange.scoring.types import ScoringData


def score_effectiveness(data: ScoringData) -> tuple[list[ScoreComponent], list[ScorePenalty]]:
    truth = data.truth
    actions = data.actions
    evidence = data.evidence
    compromised = truth.compromised_identity
    if compromised is None:
        no_compromise = data.disposition == Disposition.BENIGN
        grounded_evidence = [
            e for e in evidence if not data.observable_facts or e.fact in data.observable_facts
        ]
        components = [
            ScoreComponent(
                category="effectiveness",
                component="detection",
                awarded=10 if no_compromise else 0,
                maximum=10,
                reason="Correctly concluded no confirmed compromise"
                if no_compromise
                else "Benign activity was not correctly classified",
            ),
            ScoreComponent(
                category="effectiveness",
                component="investigation accuracy",
                awarded=10 if grounded_evidence else 0,
                maximum=10,
                reason="Legitimate activity investigated"
                if grounded_evidence
                else "No investigation evidence",
            ),
            ScoreComponent(
                category="effectiveness",
                component="reconstruction",
                awarded=min(10.0, len({e.fact for e in grounded_evidence}) * 3.0),
                maximum=10,
                reason="Benign context reconstructed"
                if grounded_evidence
                else "No benign context reconstructed",
            ),
            ScoreComponent(
                category="effectiveness",
                component="containment",
                awarded=10
                if not any(
                    a.success and a.tool in {"revoke_session", "disable_identity"} for a in actions
                )
                else 0,
                maximum=10,
                reason="Correctly avoided containment"
                if not actions
                else "Unnecessary containment",
            ),
            ScoreComponent(
                category="effectiveness",
                component="speed",
                awarded=5 if no_compromise else 0,
                maximum=5,
                reason="Reached safe disposition" if no_compromise else "No safe disposition",
            ),
        ]
        return components, []
    contained_actions = [
        a
        for a in actions
        if a.success
        and (
            (a.tool == "revoke_session" and a.target in truth.compromised_sessions)
            or (a.tool == "disable_identity" and a.target == compromised)
        )
    ]
    contained = bool(contained_actions)
    grounded_evidence = [
        e
        for e in evidence
        if e.identity_id == compromised
        and (not data.observable_facts or e.fact in data.observable_facts)
    ]
    grounded = bool(grounded_evidence)
    detected = compromised in data.conclusion.lower() and grounded
    reconstruction = min(10.0, len({e.fact for e in grounded_evidence}) * 3.0)
    objective = truth.attacker_final_objective_step
    assert objective is not None
    speed = 5.0 if contained and min(a.step for a in contained_actions) < objective else 0.0
    final_objective_reached = not any(a.step < objective for a in contained_actions)
    components = [
        ScoreComponent(
            category="effectiveness",
            component="detection",
            awarded=10 if detected else 0,
            maximum=10,
            reason="Compromise identified" if detected else "Missed compromise",
        ),
        ScoreComponent(
            category="effectiveness",
            component="investigation accuracy",
            awarded=10 if grounded else 0,
            maximum=10,
            reason="Evidence targeted compromised identity"
            if grounded
            else "No accurate investigation evidence",
        ),
        ScoreComponent(
            category="effectiveness",
            component="reconstruction",
            awarded=reconstruction,
            maximum=10,
            reason="Partial observable progression reconstructed"
            if reconstruction < 10
            else "Observable progression reconstructed",
        ),
        ScoreComponent(
            category="effectiveness",
            component="containment",
            awarded=10 if contained and not final_objective_reached else 5 if contained else 0,
            maximum=10,
            reason="Compromised session safely contained"
            if contained and not final_objective_reached
            else "Attacker reached final objective before containment"
            if contained
            else "Attacker reached final objective; compromised session was not contained",
        ),
        ScoreComponent(
            category="effectiveness",
            component="speed",
            awarded=speed,
            maximum=5,
            reason="Contained before attacker final objective"
            if speed
            else "Containment did not precede attacker final objective",
        ),
    ]
    penalties: list[ScorePenalty] = []
    if not detected:
        penalties.append(
            ScorePenalty(
                code="missed-compromise",
                category="effectiveness",
                maximum_component_loss=10,
                reason="Explicit penalty: missed compromise",
            )
        )
    if final_objective_reached:
        penalties.append(
            ScorePenalty(
                code="final-objective",
                category="effectiveness",
                maximum_component_loss=10,
                reason="Explicit penalty: attacker reached final objective",
            )
        )
    return components, penalties
