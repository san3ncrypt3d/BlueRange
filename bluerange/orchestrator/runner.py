"""Benchmark execution orchestration."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from bluerange import __version__
from bluerange.agents import BaselineDefenderAgent, DefenderAgent
from bluerange.environment import Environment
from bluerange.models import (
    ActionRecord,
    AgentContext,
    AutonomyLevel,
    BenchmarkResult,
    Disposition,
    Evidence,
)
from bluerange.scenarios import EvidenceProfile, scenario_hash
from bluerange.scenarios._evaluator import build_evaluator_instance
from bluerange.scenarios.autonomy_risk import build_risk_instance
from bluerange.scoring import ScoreInput, score_run
from bluerange.tools import ToolController

from .result import semantic_fingerprint


def run_benchmark(
    scenario_id: str,
    agent_id: str,
    autonomy: str,
    seed: int,
    agent: DefenderAgent | None = None,
    profile: EvidenceProfile | str = EvidenceProfile.COMPLETE,
    control: bool = False,
) -> BenchmarkResult:
    scenario_path = Path("scenarios/identity_compromise")
    instance = (
        build_risk_instance(seed, profile, control)
        if scenario_id == "autonomy-risk-002"
        else build_evaluator_instance(seed, profile, control)
    )
    if scenario_id == "autonomy-risk-002":
        scenario_path = Path("scenarios/autonomy_risk_002")
    scenario = instance.scenario
    if scenario.id != scenario_id:
        raise ValueError(f"unknown scenario: {scenario_id}")
    if seed < 0:
        raise ValueError("seed must be non-negative")
    defender = agent or (BaselineDefenderAgent() if agent_id == "baseline" else None)
    if defender is None:
        raise ValueError(f"unknown agent: {agent_id}")
    level = AutonomyLevel(autonomy)
    environment = Environment(scenario)
    controller = ToolController(environment, level, defender.id)
    defender.reset(AgentContext(scenario_id=scenario.id, autonomy=level, seed=seed))
    evidence: list[Evidence] = []
    actions: list[ActionRecord] = []
    conclusion = narrative = ""
    disposition = None
    for step in range(1, scenario.max_steps + 1):
        if level == AutonomyLevel.A0 and step > 1:
            break
        decision = defender.step(
            environment.observe(step),
            controller.available_tools if level != AutonomyLevel.A0 else (),
        )
        evidence.extend(decision.evidence)
        conclusion = decision.conclusion or conclusion
        disposition = decision.disposition if decision.disposition.value != "UNKNOWN" else disposition
        narrative = decision.narrative or narrative
        if level == AutonomyLevel.A0:
            continue
        for call in decision.tool_calls:
            result = controller.invoke(call, step)
            if call.name in {"revoke_session", "disable_identity"}:
                target = str(
                    call.arguments.get("session_id") or call.arguments.get("identity_id") or ""
                )
                actions.append(
                    ActionRecord(step=step, tool=call.name, target=target, success=result.success)
                )
    scored = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=actions,
            evidence=evidence,
            conclusion=conclusion,
            disposition=disposition or Disposition.UNKNOWN,
            narrative=narrative,
            autonomy=level,
            tool_calls=len(controller.history),
            audited_attempts=controller.history,
            observable_facts=frozenset(event.detail for event in scenario.telemetry),
        )
    )
    start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seed)
    values = dict(
        bluerange_version=__version__,
        scenario_id=scenario.id,
        scenario_version=scenario.version,
        scenario_hash=scenario_hash(scenario_path),
        agent_id=defender.id,
        instance_fingerprint=instance.instance_fingerprint,
        evidence_profile=instance.evidence_profile.value,
        model_id=getattr(getattr(defender, "provider", None), "model_id", None),
        autonomy=level,
        seed=seed,
        started_at=start,
        ended_at=start + timedelta(seconds=scenario.max_steps),
        tool_history=controller.history,
        actions=actions,
        evidence=evidence,
        conclusion=conclusion,
        disposition=disposition or Disposition.UNKNOWN,
        narrative=narrative,
        categories=scored.categories,
        score_breakdown=scored.breakdown,
        penalties=scored.penalties,
        score_reasons=scored.reasons,
        final_score=scored.final_score,
    )
    # Values are already typed models produced in this function; bypass only the
    # fingerprint validator while deriving the fingerprint for the final validated model.
    provisional = BenchmarkResult.model_construct(
        semantic_fingerprint="0" * 64,
        **values,  # type: ignore[arg-type]
    )
    return BenchmarkResult(semantic_fingerprint=semantic_fingerprint(provisional), **values)
