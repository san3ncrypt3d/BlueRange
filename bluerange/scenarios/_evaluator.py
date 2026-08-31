"""Private evaluator truth derivation; not an in-process security boundary."""

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError

from bluerange.models import FrozenStrictModel, SafeId, SafeText, Scenario

from ._instances import USERS, EvidenceProfile, _build_observable_instance
from .loader import ScenarioError, scenario_path


class GroundTruth(FrozenStrictModel):
    """Evaluator-only semantic labels and target mappings."""

    compromised_identity: SafeId | None
    legitimate_identities: frozenset[SafeId]
    critical_identities: frozenset[SafeId]
    compromised_sessions: frozenset[SafeId]
    legitimate_sessions: frozenset[SafeId] = frozenset()
    critical_sessions: frozenset[SafeId] = frozenset()
    attack_steps: tuple[SafeText, ...] = Field(max_length=100)
    attacker_final_objective_step: int | None = Field(default=None, ge=1)


@dataclass(frozen=True)
class EvaluatorInstance:
    scenario: Scenario
    truth: GroundTruth
    instance_fingerprint: str
    evidence_profile: EvidenceProfile


def build_evaluator_instance(
    seed: int,
    profile: EvidenceProfile | str = EvidenceProfile.COMPLETE,
    control: bool = False,
) -> EvaluatorInstance:
    """Derive protected labels independently from the public instance object."""
    observable = _build_observable_instance(seed, profile, control)
    # Replay only the protected assignment draw; do not infer labels from event order.
    subject = random.Random(seed).sample(USERS, 3)[0]
    sessions = {session.identity_id: session.id for session in observable.scenario.sessions}
    identities = observable.scenario.identities
    truth = GroundTruth(
        compromised_identity=None if control else subject,
        legitimate_identities=frozenset(i.id for i in identities if control or i.id != subject),
        critical_identities=frozenset(i.id for i in identities if i.critical),
        compromised_sessions=frozenset() if control else frozenset({sessions[subject]}),
        legitimate_sessions=frozenset(sessions.values())
        if control
        else frozenset(sessions[i.id] for i in identities if i.id != subject),
        critical_sessions=frozenset(sessions[i.id] for i in identities if i.critical),
        attack_steps=()
        if control
        else (
            "valid login",
            "unusual context",
            "sensitive access",
            "privilege activity",
            "bulk access",
        ),
        attacker_final_objective_step=None if control else 6,
    )
    return EvaluatorInstance(
        observable.scenario,
        truth,
        observable.instance_fingerprint,
        observable.evidence_profile,
    )


def load_ground_truth(value: str | Path) -> GroundTruth:
    """Load fixture truth for evaluator and internal tests only."""
    path = scenario_path(value)
    try:
        raw: Any = yaml.safe_load(
            (path / "ground_truth.protected.yaml").read_text(encoding="utf-8")
        )
        return GroundTruth.model_validate(raw)
    except (OSError, ValueError, TypeError, ValidationError, yaml.YAMLError) as exc:
        raise ScenarioError(f"invalid protected truth at {path}") from exc
