"""Strict investigation tool argument schemas."""

from typing import Annotated

from pydantic import Field

from bluerange.models import SafeId, StrictModel


class QueryArgs(StrictModel):
    query: Annotated[str, Field(min_length=1, max_length=500)]


class IdentityArgs(StrictModel):
    identity_id: SafeId


class AssetArgs(StrictModel):
    asset_id: SafeId


INVESTIGATION = {
    "search_logs",
    "inspect_identity",
    "get_authentication_history",
    "get_active_sessions",
    "get_asset_context",
}
