"""BlueRange command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from bluerange.experiment import fake_provider, run_experiment, save_experiment
from bluerange.experiment002r import PREFLIGHT_PATH, provider_preflight
from bluerange.models import AutonomyLevel, BenchmarkResult
from bluerange.models.gateway import provider_from_config
from bluerange.models.schemas import ExperimentResult, RuntimeBudgets
from bluerange.orchestrator import run_benchmark, save_result
from bluerange.scenarios import EvidenceProfile, ScenarioError, load_scenario

app = typer.Typer(no_args_is_help=True, help="Benchmark safe autonomous cyber defenders.")


@app.command("provider-check")
def provider_check(
    provider: Annotated[str, typer.Option()],
    model: Annotated[str, typer.Option()],
    protocol: Annotated[str, typer.Option()],
) -> None:
    """Perform one safe real provider/protocol compatibility preflight."""
    artifact = provider_preflight(provider, model, protocol)
    typer.echo(f"Provider preflight: {'PASS' if artifact['passed'] else 'FAIL'}")
    typer.echo(f"Saved: {PREFLIGHT_PATH.resolve()}")
    if not artifact["passed"]:
        raise typer.Exit(1)


@app.command("list-scenarios")
def list_scenarios() -> None:
    """List installed benchmark scenarios."""
    scenario = load_scenario("scenarios/identity_compromise")
    typer.echo(f"{scenario.id}\t{scenario.version}\t{scenario.name}")


@app.command()
def describe(scenario_id: str) -> None:
    """Describe a scenario without exposing evaluator truth."""
    scenario = load_scenario(scenario_id)
    typer.echo(f"{scenario.name} ({scenario.id} v{scenario.version})")
    typer.echo(scenario.description)
    typer.echo(f"Maximum steps: {scenario.max_steps}; default seed: {scenario.seed}")


@app.command()
def run(
    scenario: Annotated[str, typer.Option()] = "identity-compromise-001",
    agent: Annotated[str, typer.Option()] = "baseline",
    autonomy: Annotated[str, typer.Option()] = "A2",
    seed: Annotated[int, typer.Option()] = 42,
    output: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Run a benchmark and optionally save canonical JSON."""
    result = run_benchmark(scenario, agent, autonomy, seed)
    if output:
        save_result(result, output)
        typer.echo(f"Saved: {output.resolve()}")
    typer.echo(f"Score: {result.final_score:.1f}/100")
    typer.echo(f"Semantic fingerprint: {result.semantic_fingerprint}")


@app.command("validate-scenario")
def validate_scenario(path: Path) -> None:
    """Validate a public scenario bundle."""
    try:
        scenario = load_scenario(path)
    except ScenarioError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"Valid: {scenario.id} v{scenario.version} ({len(scenario.telemetry)} events)")


@app.command()
def results(path: Path) -> None:
    """Render a saved canonical result summary."""
    try:
        result = BenchmarkResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        typer.echo(f"Invalid result: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(
        f"{result.scenario_id} | {result.agent_id} | {result.autonomy} | {result.final_score:.1f}/100"
    )
    for category in result.categories:
        typer.echo(f"  {category.category}: {category.score:g}/{category.maximum:g}")
    for component in result.score_breakdown:
        typer.echo(
            f"  {component.category}/{component.component}: {component.awarded:g}/{component.maximum:g} — {component.reason}"
        )
    typer.echo(f"Fingerprint: {result.semantic_fingerprint}")


@app.command()
def experiment(
    scenario: Annotated[str, typer.Option()] = "identity-compromise-001",
    agent: Annotated[str, typer.Option()] = "llm",
    model: Annotated[str, typer.Option()] = "fake-defender-v1",
    autonomy: Annotated[str, typer.Option()] = "A1,A2,A3",
    seeds: Annotated[str, typer.Option()] = "101,102,103,104",
    profiles: Annotated[str, typer.Option()] = "COMPLETE",
    output: Annotated[Path, typer.Option()] = Path("results/experiment.json"),
    provider: Annotated[str | None, typer.Option()] = None,
    base_url: Annotated[str | None, typer.Option()] = None,
    timeout: Annotated[float, typer.Option()] = 30,
    fake_model: Annotated[bool, typer.Option("--fake-model")] = False,
    model_turns: Annotated[int, typer.Option()] = 12,
    investigation_calls: Annotated[int, typer.Option()] = 8,
    response_actions: Annotated[int, typer.Option()] = 2,
) -> None:
    """Run paired attack/control v0.2 LLM experiments."""
    if agent != "llm":
        raise typer.BadParameter("v0.2 experiments currently require --agent llm")
    selected = "fake" if fake_model else provider
    factory = (
        (lambda: fake_provider(model))
        if selected == "fake"
        else (lambda: provider_from_config(selected, model, base_url, timeout))
    )
    result = run_experiment(
        scenario,
        [int(item) for item in seeds.split(",")],
        [AutonomyLevel(item) for item in autonomy.split(",")],
        [EvidenceProfile(item) for item in profiles.split(",")],
        factory,
        RuntimeBudgets(
            model_turns=model_turns,
            investigation_calls=investigation_calls,
            response_actions=response_actions,
        ),
    )
    save_experiment(result, output)
    typer.echo(f"Saved experiment: {output.resolve()}")
    typer.echo(f"Runs: {len(result.runs)}; mean score: {result.metrics.mean_score:.2f}")


@app.command("experiment-results")
def experiment_results(path: Path) -> None:
    """Validate and summarize a saved v0.2 experiment envelope."""
    try:
        result = ExperimentResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        typer.echo(f"Invalid experiment: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(
        f"{result.scenario_id} | {len(result.runs)} paired runs | {result.metrics.mean_score:.2f} mean"
    )
    typer.echo(
        f"Attack detection: {result.metrics.attack_detection:.3f}; benign specificity: {result.metrics.benign_specificity:.3f}"
    )


if __name__ == "__main__":
    app()
