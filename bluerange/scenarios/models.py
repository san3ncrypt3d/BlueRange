"""Strict public and evaluator-only scenario models."""

from pydantic import Field

from bluerange.models import FrozenStrictModel, SafeId, SafeText, Scenario, TelemetryEvent


class GroundTruth(FrozenStrictModel):
    compromised_identity: SafeId
    legitimate_identities: frozenset[SafeId]
    critical_identities: frozenset[SafeId]
    compromised_sessions: frozenset[SafeId]
    attack_steps: tuple[SafeText, ...] = Field(min_length=1, max_length=100)
    attacker_final_objective_step: int = Field(ge=1)


__all__ = ["GroundTruth", "Scenario", "TelemetryEvent"]
