"""Scenario loading across the public/protected boundary."""

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from bluerange.models import Scenario, TelemetryEvent

from .models import GroundTruth


class ScenarioError(ValueError):
    pass


def scenario_path(value: str | Path) -> Path:
    path = Path(value)
    return Path("scenarios/identity_compromise") if path.name == "identity-compromise-001" else path


def load_scenario(value: str | Path) -> Scenario:
    path = scenario_path(value)
    try:
        raw = yaml.safe_load((path / "scenario.yaml").read_text(encoding="utf-8"))
        events = json.loads((path / "telemetry.json").read_text(encoding="utf-8"))
        return Scenario.model_validate({**raw, "telemetry": [TelemetryEvent.model_validate(e) for e in events]})
    except (OSError, ValueError, TypeError, ValidationError, yaml.YAMLError) as exc:
        raise ScenarioError(f"invalid scenario at {path}") from exc


def load_ground_truth(value: str | Path) -> GroundTruth:
    path = scenario_path(value)
    try:
        raw: Any = yaml.safe_load((path / "ground_truth.protected.yaml").read_text(encoding="utf-8"))
        return GroundTruth.model_validate(raw)
    except (OSError, ValueError, TypeError, ValidationError, yaml.YAMLError) as exc:
        raise ScenarioError(f"invalid protected truth at {path}") from exc


def scenario_hash(value: str | Path) -> str:
    path = scenario_path(value)
    digest = hashlib.sha256()
    for name in ("scenario.yaml", "telemetry.json"):
        digest.update((path / name).read_bytes())
    return digest.hexdigest()
