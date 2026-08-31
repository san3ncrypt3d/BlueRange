"""Canonical result serialization and semantic fingerprints."""

import hashlib
import json
from pathlib import Path
from typing import Any

from bluerange.models import BenchmarkResult


def stable_content(result: BenchmarkResult) -> dict[str, Any]:
    data = result.model_dump(mode="json")
    data.pop("started_at", None)
    data.pop("ended_at", None)
    data.pop("semantic_fingerprint", None)
    for audit in data["tool_history"]:
        audit.pop("timestamp", None)
        audit.pop("latency_ms", None)
    return data


def semantic_fingerprint(result: BenchmarkResult) -> str:
    encoded = json.dumps(stable_content(result), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def save_result(result: BenchmarkResult, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
