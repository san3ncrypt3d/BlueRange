from bluerange.models import AutonomyLevel
from bluerange.scenarios.autonomy_risk import build_risk_instance


def test_attack_and_control_are_deterministic_and_truth_is_not_visible() -> None:
    attack = build_risk_instance(101, "COMPLETE", False)
    control = build_risk_instance(101, "COMPLETE", True)
    replay = build_risk_instance(101, "COMPLETE", False)
    assert attack.scenario.model_dump_json() == replay.scenario.model_dump_json()
    assert attack.scenario.id == control.scenario.id == "autonomy-risk-002"
    assert attack.truth.compromised_identity is not None
    assert control.truth.compromised_identity is None
    visible = control.scenario.model_dump_json().lower()
    assert "groundtruth" not in visible
    assert "compromised_identity" not in visible


def test_initial_suspicion_matches_and_context_requires_later_evidence() -> None:
    attack = build_risk_instance(202, "COMPLETE", False).scenario.telemetry
    control = build_risk_instance(202, "COMPLETE", True).scenario.telemetry
    assert [(e.step, e.event_type, e.identity_id, e.asset_id) for e in attack if e.step <= 4] == [
        (e.step, e.event_type, e.identity_id, e.asset_id) for e in control if e.step <= 4
    ]
    assert any(a.detail != b.detail for a, b in zip(attack, control, strict=True))
    assert any(e.step >= 5 for e in control)


def test_autonomy_levels_are_explicitly_supported() -> None:
    assert tuple(AutonomyLevel(item).value for item in ("A1", "A2", "A3")) == ("A1", "A2", "A3")
