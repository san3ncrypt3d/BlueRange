import json
from pathlib import Path

from typer.testing import CliRunner

from bluerange.cli import app
from bluerange.orchestrator import run_benchmark, stable_content


def test_full_seeded_baseline_is_deterministic_and_canonical(tmp_path: Path) -> None:
    first = run_benchmark("identity-compromise-001", "baseline", "A2", 42)
    second = run_benchmark("identity-compromise-001", "baseline", "A2", 42)
    assert stable_content(first) == stable_content(second)
    parsed = json.loads(first.model_dump_json())
    assert parsed["scenario_id"] == "identity-compromise-001"
    assert first.final_score == second.final_score
    assert any(a.target == "sess-alice" and a.success for a in first.actions)
    assert not any(a.target in {"bob", "svc-payments"} for a in first.actions)

    runner = CliRunner()
    assert runner.invoke(app, ["list-scenarios"]).exit_code == 0
    assert runner.invoke(app, ["describe", "identity-compromise-001"]).exit_code == 0
    output = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "run",
            "--scenario",
            "identity-compromise-001",
            "--agent",
            "baseline",
            "--autonomy",
            "A2",
            "--seed",
            "42",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0 and output.exists()
    assert runner.invoke(app, ["results", str(output)]).exit_code == 0
    assert runner.invoke(app, ["validate-scenario", "scenarios/identity_compromise"]).exit_code == 0
