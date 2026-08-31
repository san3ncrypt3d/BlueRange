"""Reproducible local integrity experiment; not installed as production support."""

import argparse
import json
import statistics
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bluerange.agents import BaselineDefenderAgent, DefenderAgent
from bluerange.models import BenchmarkResult
from bluerange.orchestrator import run_benchmark
from bluerange.scenarios import EvidenceProfile
from bluerange.scenarios._evaluator import build_evaluator_instance
from tests.support.agents import (
    DisableEverythingAgent,
    DoNothingAgent,
    MinimalInvestigatorAgent,
    OracleDefender,
    OverconfidentAgent,
    RandomResponderAgent,
    SafeControlAgent,
)

ATTACK_SEEDS = tuple(range(101, 121))
BENIGN_SEEDS = tuple(range(9001, 9011))
PROFILES = tuple(EvidenceProfile)


def assignment(seed: int, seeds: tuple[int, ...]) -> EvidenceProfile:
    return PROFILES[seeds.index(seed) % len(PROFILES)]


def run_validation() -> dict[str, Any]:
    factories: dict[str, Callable[[int, EvidenceProfile, bool], DefenderAgent]] = {
        "baseline": lambda seed, profile, control: BaselineDefenderAgent(),
        "do-nothing": lambda seed, profile, control: DoNothingAgent(),
        "disable-everything": lambda seed, profile, control: DisableEverythingAgent(),
        "random-responder": lambda seed, profile, control: RandomResponderAgent(),
        "overconfident": lambda seed, profile, control: OverconfidentAgent(),
        "minimal-investigator": lambda seed, profile, control: MinimalInvestigatorAgent(),
        "safe-control": lambda seed, profile, control: SafeControlAgent(),
        "oracle": lambda seed, profile, control: OracleDefender(
            build_evaluator_instance(seed, profile, control).truth
        ),
    }
    runs: list[dict[str, Any]] = []
    for label, factory in factories.items():
        for control, seeds in ((False, ATTACK_SEEDS), (True, BENIGN_SEEDS)):
            for seed in seeds:
                profile = assignment(seed, seeds)
                autonomy = "A3" if label == "disable-everything" else "A2"
                result = run_benchmark(
                    "identity-compromise-001",
                    "validation",
                    autonomy,
                    seed,
                    factory(seed, profile, control),
                    profile,
                    control,
                )
                runs.append(_run_record(label, control, result))
    return {
        "schema_version": "1.0",
        "attack_seeds": list(ATTACK_SEEDS),
        "benign_seeds": list(BENIGN_SEEDS),
        "profile_assignment": "ordered seed index modulo [COMPLETE, PARTIAL, AMBIGUOUS, NOISY]",
        "standard_deviation": "population for enumerated predetermined validation set; sample also reported",
        "agents": {
            label: _summary([run for run in runs if run["agent"] == label]) for label in factories
        },
        "runs": runs,
    }


def _run_record(label: str, control: bool, result: BenchmarkResult) -> dict[str, Any]:
    containment_score = _component(result, "containment")
    containment = containment_score > 0 if not control else containment_score == 0
    detection = _component(result, "detection") > 0
    return {
        "agent": label,
        "seed": result.seed,
        "profile": result.evidence_profile,
        "instance_fingerprint": result.instance_fingerprint,
        "control_set": "benign" if control else "attack",
        "score": result.final_score,
        "detection": detection,
        "containment": containment,
        "tool_calls": len(result.tool_history),
        "safety": _category(result, "safety"),
        "semantic_fingerprint": result.semantic_fingerprint,
    }


def _summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    attack = [run for run in runs if run["control_set"] == "attack"]
    benign = [run for run in runs if run["control_set"] == "benign"]
    scores = [run["score"] for run in attack]
    return {
        "attack_score": _distribution(scores),
        "benign_score": _distribution([run["score"] for run in benign]),
        "attack_detection_rate": _rate(attack, "detection"),
        "attack_containment_rate": _rate(attack, "containment"),
        "false_positive_containment_rate": _rate(benign, "containment"),
        "benign_specificity": 1.0 - _rate(benign, "containment"),
        "average_tool_calls": statistics.fmean(run["tool_calls"] for run in runs),
        "average_safety": statistics.fmean(run["safety"] for run in runs),
    }


def _distribution(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "population_stddev": statistics.pstdev(values),
        "sample_stddev": statistics.stdev(values),
        "min": min(values),
        "max": max(values),
    }


def _rate(runs: list[dict[str, Any]], key: str) -> float:
    return sum(bool(run[key]) for run in runs) / len(runs)


def _category(result: BenchmarkResult, name: str) -> float:
    return next(item.score for item in result.categories if item.category == name)


def _component(result: BenchmarkResult, name: str) -> float:
    return next(item.awarded for item in result.score_breakdown if item.component == name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=Path("results/benchmark-validation-v0.1.json")
    )
    args = parser.parse_args()
    measured = run_validation()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(measured, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(measured["agents"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
