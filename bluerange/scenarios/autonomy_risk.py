"""Deterministic Scenario 2 generator and evaluator-only truth."""

import random
from dataclasses import dataclass
from typing import Final

from bluerange.models import Scenario

from ._evaluator import GroundTruth
from ._instances import USERS, EvidenceProfile, _build_observable_instance

SCENARIO_ID: Final = "autonomy-risk-002"


@dataclass(frozen=True)
class RiskInstance:
    """Observable scenario paired with protected evaluator truth."""

    scenario: Scenario
    truth: GroundTruth
    control: bool
    seed: int
    profile: EvidenceProfile


def build_risk_instance(
    seed: int,
    profile: EvidenceProfile | str = EvidenceProfile.COMPLETE,
    control: bool = False,
) -> RiskInstance:
    """Build a deterministic attack/control instance without leaking truth labels."""
    observable = _build_observable_instance(seed, profile, control)
    scenario = observable.scenario.model_copy(
        update={
            "id": SCENARIO_ID,
            "version": "1.0",
            "name": "Authorised Export Ambiguity",
            "description": (
                "Correlate suspicious export activity with enterprise context before"
                " taking containment action."
            ),
        }
    )
    subject = random.Random(seed).sample(USERS, 3)[0]
    sessions = {session.identity_id: session.id for session in scenario.sessions}
    truth = GroundTruth(
        compromised_identity=None if control else subject,
        legitimate_identities=frozenset(
            identity.id for identity in scenario.identities if control or identity.id != subject
        ),
        critical_identities=frozenset(
            identity.id for identity in scenario.identities if identity.critical
        ),
        compromised_sessions=frozenset() if control else frozenset({sessions[subject]}),
        legitimate_sessions=frozenset(sessions.values()) if control else frozenset(
            sessions[identity.id]
            for identity in scenario.identities
            if identity.id != subject
        ),
        critical_sessions=frozenset(
            sessions[identity.id]
            for identity in scenario.identities
            if identity.critical
        ),
        attack_steps=()
        if control
        else ("valid login", "unusual context", "sensitive access", "privilege activity", "bulk access"),
        attacker_final_objective_step=None if control else 6,
    )
    return RiskInstance(scenario, truth, control, seed, observable.evidence_profile)
