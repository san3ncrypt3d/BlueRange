"""Structured operational logging for benchmark control-plane events."""

import json
import logging
from typing import Any

from .models import AuditRecord, TelemetryEvent

__all__ = ["AuditRecord", "TelemetryEvent", "log_audit_event"]

LOGGER = logging.getLogger("bluerange.audit")


def log_audit_event(event: dict[str, Any]) -> None:
    """Emit an audit event as compact structured JSON through standard logging."""
    LOGGER.info(json.dumps(event, sort_keys=True, separators=(",", ":")))
