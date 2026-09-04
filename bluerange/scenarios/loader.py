"""Scenario loading across the public/protected boundary."""

import hashlib
import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from bluerange.models import Scenario, TelemetryEvent


class ScenarioError(ValueError):
    pass


def scenario_path(value: str | Path) -> Path:
    path = Path(value)
    if path.name in {"identity-compromise-001", "autonomy-risk-002", "identity_compromise", "autonomy_risk_002"}:
        bundle = "identity_compromise" if path.name in {"identity-compromise-001", "identity_compromise"} else "autonomy_risk_002"
        local = Path("scenarios") / bundle
        installed = Path(__file__).resolve().parents[2] / "scenarios" / bundle
        return local if local.exists() else installed
    return path


def load_scenario(value: str | Path) -> Scenario:
    path = scenario_path(value)
    try:
        raw = yaml.safe_load((path / "scenario.yaml").read_text(encoding="utf-8"))
        events = json.loads((path / "telemetry.json").read_text(encoding="utf-8"))
        return Scenario.model_validate(
            {**raw, "telemetry": [TelemetryEvent.model_validate(e) for e in events]}
        )
    except (OSError, ValueError, TypeError, ValidationError, yaml.YAMLError) as exc:
        raise ScenarioError(f"invalid scenario at {path}") from exc


def scenario_hash(value: str | Path) -> str:
    path = scenario_path(value)
    digest = hashlib.sha256()
    for name in ("scenario.yaml", "telemetry.json"):
        digest.update((path / name).read_bytes())
    return digest.hexdigest()
