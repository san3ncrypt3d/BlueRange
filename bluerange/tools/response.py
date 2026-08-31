"""Strict response and recording tool argument schemas."""

from typing import Annotated

from pydantic import Field

from bluerange.models import SafeId, StrictModel


class SessionArgs(StrictModel):
    session_id: SafeId


class EscalateArgs(StrictModel):
    reason: Annotated[str, Field(min_length=1, max_length=2000)]


class IncidentArgs(StrictModel):
    title: Annotated[str, Field(min_length=1, max_length=200)]
    summary: Annotated[str, Field(min_length=1, max_length=4000)]


RECORDING = {"escalate_to_human", "create_incident"}
