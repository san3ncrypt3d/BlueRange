"""BlueRange command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from bluerange.models import BenchmarkResult
from bluerange.orchestrator import run_benchmark, save_result
from bluerange.scenarios import ScenarioError, load_scenario

app = typer.Typer(no_args_is_help=True, help="Benchmark safe autonomous cyber defenders.")


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


if __name__ == "__main__":
    app()
