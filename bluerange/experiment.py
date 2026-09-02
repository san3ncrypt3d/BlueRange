"""v0.2 experiment execution and aggregation without changing the v0.1 runner."""

import json
import statistics
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from bluerange import __version__
from bluerange.agents.llm_agent import LLMDefenderAgent
from bluerange.environment import Environment
from bluerange.models import ActionRecord, AgentContext, AutonomyLevel, BenchmarkResult
from bluerange.models.gateway import FakeModelProvider, ModelProvider
from bluerange.models.schemas import (
    ExperimentMetrics,
    ExperimentResult,
    ExperimentRun,
    ProviderRequest,
    RuntimeBudgets,
)
from bluerange.orchestrator.result import semantic_fingerprint
from bluerange.scenarios import EvidenceProfile, scenario_hash
from bluerange.scenarios._evaluator import build_evaluator_instance
from bluerange.scoring import ScoreInput, score_run
from bluerange.tools import ToolController


def _fake_script(request: ProviderRequest, index: int) -> str:
    public = json.loads(request.messages[-1].content)
    events = [event for observation in public["observations"] for event in observation["events"]]
    attack_markers = (
        "unmanaged device",
        "no matching travel record",
        "outside the approved workflow",
        "without a business justification",
    )
    benign_markers = ("approved", "scheduled", "reconciled", "corporate vpn")
    identities = sorted({event["identity_id"] for event in events})

    def evidence_strength(identity: str) -> tuple[int, str]:
        details = " ".join(
            event["detail"].lower() for event in events if event["identity_id"] == identity
        )
        strength = sum(marker in details for marker in attack_markers)
        strength -= sum(marker in details for marker in benign_markers)
        return strength, identity

    strength, subject = max(evidence_strength(identity) for identity in identities)
    attack = strength > 0
    facts = [event["detail"] for event in events if event["identity_id"] == subject][-3:]
    common = {
        "assessment": {
            "attack_suspected": attack,
            "confidence": 0.95 if attack else 0.05,
            "subject_identity_id": subject,
            "summary": f"Observable activity for {subject} is {'malicious' if attack else 'benign'}.",
            "evidence": facts,
            "disposition": "COMPROMISE" if attack else "BENIGN",
        },
        "reason": "Decision based only on observable telemetry.",
    }
    if not attack:
        common["next_action"] = {"type": "final", "response": "No containment is warranted."}
    elif index == 0:
        common["next_action"] = {
            "type": "tool",
            "name": "get_active_sessions",
            "arguments": {"identity_id": subject},
        }
    elif index == 1:
        sessions = public["own_tool_results"][-1].get("data", {}).get("sessions", [])
        session = sessions[0]["id"] if sessions else "missing-session"
        common["next_action"] = {
            "type": "recommendation" if public["autonomy"] == "A1" else "tool",
            "name": "revoke_session",
            "arguments": {"session_id": session},
        }
    else:
        common["next_action"] = {
            "type": "final",
            "response": "Compromise assessed and proportional session containment requested.",
        }
    return json.dumps(common)


def fake_provider(model_id: str = "fake-defender-v1") -> FakeModelProvider:
    return FakeModelProvider(model_id=model_id, script=_fake_script)


def _run_one(
    scenario_id: str,
    seed: int,
    autonomy: AutonomyLevel,
    profile: EvidenceProfile,
    control: bool,
    provider: ModelProvider,
    budgets: RuntimeBudgets,
    run_id: str,
    system_prompt: str | None = None,
    temperature: float = 0.2,
    top_p: float = 0.9,
    model_seed: int = 17,
    request_timeout: float = 30,
) -> ExperimentRun:
    started = datetime.now(UTC)
    instance = build_evaluator_instance(seed, profile, control)
    scenario = instance.scenario
    environment = Environment(scenario)
    agent = LLMDefenderAgent(
        provider,
        budgets,
        system_prompt=system_prompt,
        temperature=temperature,
        top_p=top_p,
        model_seed=model_seed,
        request_timeout=request_timeout,
    )
    controller = ToolController(environment, autonomy, agent.id)
    agent.reset(AgentContext(scenario_id=scenario_id, autonomy=autonomy, seed=seed))
    for step in range(1, scenario.max_steps + 1):
        agent.observe(environment.observe(step))
    decision = agent.run(
        controller=controller,
        description=scenario.description,
        run_id=run_id,
        profile=profile.value,
    )

    actions = [
        ActionRecord(
            step=a.step,
            tool=a.tool,
            target=a.target,
            success=bool(a.tool_success),
        )
        for a in agent.action_attempts
        if a.tool in {"revoke_session", "disable_identity"}
        and a.execution_status == "EXECUTED"
        and a.target is not None
    ]
    scored = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=actions,
            evidence=decision.evidence,
            conclusion=decision.conclusion,
            disposition=decision.disposition,
            narrative=decision.narrative,
            autonomy=autonomy,
            tool_calls=len(controller.history),
            audited_attempts=controller.history,
            observable_facts=frozenset(event.detail for event in scenario.telemetry),
        )
    )
    ended = datetime.now(UTC)
    values = dict(
        bluerange_version=__version__,
        scenario_id=scenario.id,
        scenario_version=scenario.version,
        scenario_hash=scenario_hash(Path("scenarios/identity_compromise")),
        agent_id=agent.id,
        instance_fingerprint=instance.instance_fingerprint,
        evidence_profile=profile.value,
        model_id=provider.model_id,
        autonomy=autonomy,
        seed=seed,
        started_at=started,
        ended_at=ended,
        tool_history=controller.history,
        actions=actions,
        evidence=decision.evidence,
        conclusion=decision.conclusion,
        disposition=decision.disposition,
        narrative=decision.narrative,
        categories=scored.categories,
        score_breakdown=scored.breakdown,
        penalties=scored.penalties,
        score_reasons=scored.reasons,
        final_score=scored.final_score,
    )
    provisional = BenchmarkResult.model_construct(
        semantic_fingerprint="0" * 64,
        **values,  # type: ignore[arg-type]
    )
    result = BenchmarkResult(semantic_fingerprint=semantic_fingerprint(provisional), **values)
    return ExperimentRun(
        run_id=run_id,
        kind="benign" if control else "attack",
        result=result,
        model_audits=agent.audits,
        action_attempts=agent.action_attempts,
    )


def aggregate_metrics(runs: list[ExperimentRun]) -> ExperimentMetrics:
    """Aggregate only evaluator-scored outcomes from individual canonical runs."""
    scores = [run.result.final_score for run in runs]
    attacks = [run for run in runs if run.kind == "attack"]
    benign = [run for run in runs if run.kind == "benign"]
    # Refuse to publish benchmark aggregates for an incomplete matrix rather than
    # dividing by zero or reporting an absent rate as a defender score of zero.
    if not runs:
        raise ValueError("cannot aggregate an experiment with no completed runs")
    if not attacks or not benign:
        raise ValueError("cannot aggregate an experiment without paired attack and benign runs")

    def credited(run: ExperimentRun, component: str) -> bool:
        scored = next(
            (item for item in run.result.score_breakdown if item.component == component), None
        )
        if scored is None:
            raise ValueError(f"run {run.run_id} has no scored component {component!r}")
        return scored.awarded > 0

    false_positive_containment = sum(not credited(run, "containment") for run in benign) / len(
        benign
    )
    safety = [
        next(category.score for category in run.result.categories if category.category == "safety")
        for run in runs
    ]
    audits = [audit for run in runs for audit in run.model_audits]
    costs = [audit.cost for audit in audits if audit.cost is not None]
    return ExperimentMetrics(
        mean_score=statistics.fmean(scores),
        median_score=statistics.median(scores),
        population_stddev=statistics.pstdev(scores),
        attack_detection=sum(credited(run, "detection") for run in attacks) / len(attacks),
        correct_attack_containment=sum(credited(run, "containment") for run in attacks)
        / len(attacks),
        benign_specificity=1 - false_positive_containment,
        false_positive_containment=false_positive_containment,
        mean_operational_safety=statistics.fmean(safety),
        average_tool_calls=statistics.fmean(len(run.result.tool_history) for run in runs),
        total_tokens=sum(audit.usage.total_tokens for audit in audits),
        total_latency_ms=sum(audit.latency_ms for audit in audits),
        total_cost=sum(costs) if costs else None,
    )


def run_experiment(
    scenario_id: str,
    seeds: list[int],
    autonomies: list[AutonomyLevel],
    profiles: list[EvidenceProfile],
    provider_factory: Callable[[], ModelProvider],
    budgets: RuntimeBudgets | None = None,
    *,
    system_prompt: str | None = None,
    temperature: float = 0.2,
    top_p: float = 0.9,
    model_seed: int = 17,
    request_timeout: float = 30,
) -> ExperimentResult:
    limits = budgets or RuntimeBudgets()
    runs: list[ExperimentRun] = []
    run_ordinal = 0
    for autonomy in autonomies:
        for profile in profiles:
            for seed in seeds:
                for control in (False, True):
                    run_ordinal += 1
                    runs.append(
                        _run_one(
                            scenario_id,
                            seed,
                            autonomy,
                            profile,
                            control,
                            provider_factory(),
                            limits,
                            f"run-{run_ordinal:06d}",
                            system_prompt,
                            temperature,
                            top_p,
                            model_seed,
                            request_timeout,
                        )
                    )
    if not runs:
        raise ValueError("experiment matrix produced no runs")
    metrics = aggregate_metrics(runs)
    if not runs[0].model_audits:
        raise ValueError("first run produced no model audits")
    first = runs[0].model_audits[0]
    return ExperimentResult(
        scenario_id=scenario_id,
        provider_id=first.provider_id,
        model_id=first.model_id,
        profiles=[p.value for p in profiles],
        seeds=seeds,
        autonomies=autonomies,
        runs=runs,
        metrics=metrics,
    )


def save_experiment(result: ExperimentResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
