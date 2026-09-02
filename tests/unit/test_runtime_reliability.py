"""End-to-end regressions for typed unresolved action attempts."""

import json
from typing import Any

import pytest

from bluerange.experiment import run_experiment
from bluerange.models import AutonomyLevel
from bluerange.models.gateway import FakeModelProvider
from bluerange.models.schemas import ProviderRequest, RuntimeBudgets
from bluerange.scenarios import EvidenceProfile


def _decision(action: dict[str, Any]) -> str:
    return json.dumps(
        {
            "assessment": {
                "attack_suspected": True,
                "confidence": 0.9,
                "subject_identity_id": "alice",
                "summary": "Synthetic assessment.",
                "evidence": [],
                "disposition": "COMPROMISE",
            },
            "next_action": action,
            "reason": "Synthetic runtime regression.",
        }
    )


@pytest.mark.parametrize(
    ("case", "action", "level", "target", "executed", "failure"),
    [
        (
            "valid target",
            {"type": "tool", "name": "disable_identity", "arguments": {"identity_id": "__observed__"}},
            AutonomyLevel.A3,
            "__observed__",
            True,
            "none",
        ),
        (
            "nonexistent target",
            {"type": "tool", "name": "disable_identity", "arguments": {"identity_id": "nobody"}},
            AutonomyLevel.A3,
            "nobody",
            True,
            "tool_failure",
        ),
        (
            "malformed target",
            {"type": "tool", "name": "revoke_session", "arguments": {"session_id": "[invalid]"}},
            AutonomyLevel.A3,
            None,
            False,
            "invalid_arguments",
        ),
        (
            "missing target",
            {"type": "tool", "name": "revoke_session", "arguments": {}},
            AutonomyLevel.A3,
            None,
            False,
            "invalid_arguments",
        ),
        (
            "wrong argument name",
            {"type": "tool", "name": "revoke_session", "arguments": {"identity_id": "alice"}},
            AutonomyLevel.A3,
            None,
            False,
            "invalid_arguments",
        ),
        (
            "wrong argument type",
            {"type": "tool", "name": "revoke_session", "arguments": {"session_id": ["x"]}},
            AutonomyLevel.A3,
            None,
            False,
            "invalid_arguments",
        ),
        (
            "denied action",
            {"type": "tool", "name": "disable_identity", "arguments": {"identity_id": "alice"}},
            AutonomyLevel.A2,
            "alice",
            False,
            "authorization_denied",
        ),
        (
            "prohibited by autonomy",
            {"type": "tool", "name": "revoke_session", "arguments": {"session_id": "session-404"}},
            AutonomyLevel.A1,
            "session-404",
            False,
            "authorization_denied",
        ),
        (
            "non-executable recommendation",
            {"type": "recommendation", "name": "revoke_session", "arguments": {"session_id": "session-404"}},
            AutonomyLevel.A3,
            "session-404",
            False,
            "recommendation_only",
        ),
        (
            "semantically invalid arguments",
            {"type": "tool", "name": "disable_identity", "arguments": {"identity_id": "[invalid]"}},
            AutonomyLevel.A3,
            None,
            False,
            "invalid_arguments",
        ),
    ],
)
def test_action_attempt_survives_complete_canonical_path(
    case: str,
    action: dict[str, Any],
    level: AutonomyLevel,
    target: str | None,
    executed: bool,
    failure: str,
) -> None:
    def scripted(_request: ProviderRequest, _index: int) -> str:
        selected = json.loads(json.dumps(action))
        if target == "__observed__":
            public = json.loads(_request.messages[-1].content)
            observed = public["observations"][0]["events"][0]["identity_id"]
            selected["arguments"]["identity_id"] = observed
        return _decision(selected)

    experiment = run_experiment(
        "identity-compromise-001",
        [101],
        [level],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=scripted),
        RuntimeBudgets(model_turns=1, investigation_calls=0, response_actions=1),
    )
    run = experiment.runs[0]
    assert len(run.action_attempts) == 1, case
    attempt = run.action_attempts[0]
    expected_target = (
        attempt.original_arguments["identity_id"] if target == "__observed__" else target
    )
    expected_arguments = (
        {"identity_id": expected_target} if target == "__observed__" else action["arguments"]
    )
    assert attempt.original_arguments == expected_arguments
    assert attempt.target == expected_target
    assert (attempt.execution_status == "EXECUTED") is executed
    assert attempt.safe_failure_category == failure
    assert all(record.target != "[invalid]" for record in run.result.actions)
    if not executed:
        assert not run.result.actions
    containment = next(
        item for item in run.result.score_breakdown if item.component == "containment"
    )
    if failure != "none":
        assert containment.awarded == 0
    restored = type(experiment).model_validate_json(experiment.model_dump_json())
    assert restored.runs[0].action_attempts[0].safe_failure_category == failure
