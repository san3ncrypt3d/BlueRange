"""Fresh two-run A1 canary gated by the neutral protocol laboratory."""

import hashlib
import json
from pathlib import Path
from typing import Any

from bluerange.experiment002 import MODEL, run_experiment_v2
from bluerange.models import AutonomyLevel
from bluerange.models.gateway import ModelProvider, ProviderError, provider_from_config
from bluerange.models.schemas import ProviderRequest, ProviderResponse, RuntimeBudgets
from bluerange.protocol_conformance import ProviderRequestCap
from bluerange.scenarios import EvidenceProfile

LAB_PATH = Path("results/protocol-conformance-v2.json")
CANARY_PATH = Path("results/experiment-002r-canary-2.json")
V2_PROMPT_SHA256 = "1edcb1b12b0d3ef1463c1330015fb127409c76e311323879545297826dfa9fe4"


class CappedProvider:
    """Prevent real calls once the task-wide provider-request cap is exhausted."""

    def __init__(self, provider: ModelProvider, cap: ProviderRequestCap):
        self.provider = provider
        self.cap = cap
        self.provider_id = provider.provider_id
        self.model_id = provider.model_id

    @property
    def audits(self) -> list[Any]:
        """Expose the wrapped provider's safe audit records."""
        return getattr(self.provider, "audits", [])

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        """Consume one allowance immediately before each real provider request."""
        if not self.cap.consume():
            raise ProviderError("absolute provider request cap reached")
        return self.provider.complete(request)


def run_fresh_canary() -> dict[str, Any]:
    """Run only the permitted fresh A1 attack/benign pair after the lab passes."""
    lab = json.loads(LAB_PATH.read_text(encoding="utf-8"))
    if not lab.get("lab_passed"):
        raise SystemExit("protocol lab gate failed; canary not run")
    previous = int(lab["shared_real_provider_request_cap"]["used"])
    cap = ProviderRequestCap(maximum=12, used=previous)
    experiment = run_experiment_v2(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A1],
        [EvidenceProfile.COMPLETE],
        lambda: CappedProvider(
            provider_from_config("ollama", MODEL, "http://localhost:11434/v1", 600), cap
        ),
        RuntimeBudgets(model_turns=12, investigation_calls=8, response_actions=2),
        prompt=Path("prompts/defender-v2.txt").read_text(encoding="utf-8"),
        temperature=0.2,
        top_p=0.9,
        model_seed=17,
        request_timeout=600,
    )
    runs = experiment.runs
    actual_canary_requests = cap.used - previous
    gates = {
        "exact_fresh_pair": len(runs) == 2,
        "attack_benign_pair": {run.kind for run in runs} == {"attack", "benign"},
        "a1_only": all(run.result.autonomy == AutonomyLevel.A1 for run in runs),
        "provider_success_100_percent": all(run.protocol.provider_errors == 0 for run in runs),
        "both_entered_lifecycle": all(run.protocol.post_repair_valid_turns > 0 for run in runs),
        "invalid_decisions_never_reached_controller": all(
            all(audit.get("parsed") is not None for audit in run.protocol.turn_audits)
            for run in runs
        ),
        "absolute_request_cap_respected": cap.used <= cap.maximum == 12,
        "frozen_prompt_hash_preserved": (
            hashlib.sha256(Path("prompts/defender-v2.txt").read_bytes()).hexdigest()
            == V2_PROMPT_SHA256
        ),
    }
    artifact = {
        "schema_version": "experiment-002r-canary-2-v1",
        "model": MODEL,
        "provider": "ollama",
        "parameters": {
            "output_mode": "JSON_OBJECT",
            "temperature": 0.2,
            "top_p": 0.9,
            "model_seed": 17,
            "timeout_seconds": 600,
        },
        "runs": [run.model_dump(mode="json") for run in runs],
        "gates": gates,
        "canary_passed": all(gates.values()),
        "provider_requests": actual_canary_requests,
        "shared_real_provider_request_cap": {"maximum": cap.maximum, "used": cap.used},
        "formal_002r_authorisation": "NO",
        "formal_002r_note": (
            "Formal 002R was not run and requires separate user approval even if this canary passes."
        ),
    }
    CANARY_PATH.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact


if __name__ == "__main__":
    run_fresh_canary()
