"""Cross-cutting helpers and Pydantic response models for the SSH tools."""

from __future__ import annotations

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from ..settings import CredentialProfile, Settings


def get_settings(ctx: Context) -> Settings:
    # `request_context` is only None outside an active request — never during a
    # tool call, but mypy can't see that without the assertion.
    assert ctx.request_context is not None
    return ctx.request_context.lifespan_context["settings"]


def resolve_profile(settings: Settings, name: str) -> CredentialProfile:
    """Look up a credential profile, converting config errors into a ToolError
    the agent can act on."""
    try:
        return settings.get_profile(name)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


# --- response models ------------------------------------------------------


class CommandResult(BaseModel):
    host: str
    platform: str
    command: str
    output: str = Field(..., description="Device output, with credentials redacted")
    failed: bool = Field(
        ..., description="True if the command failed — device-rejected or an SSH session error"
    )
    error: str | None = Field(
        None, description="Set when the SSH session failed mid-command (vs. a device rejection)"
    )
    elapsed_seconds: float | None = None


class MultiCommandResult(BaseModel):
    host: str
    platform: str
    failed: bool = Field(..., description="True if any command in the batch failed")
    results: list[CommandResult] = Field(default_factory=list)


class ConfigResult(BaseModel):
    host: str
    platform: str
    commands: list[str]
    output: str = Field(..., description="Per-command device output, credentials redacted")
    failed: bool = Field(..., description="True if any config command was rejected by the device")
    saved: bool = Field(False, description="True if the running config was persisted to startup")
    note: str | None = Field(
        None, description="Advisory message, e.g. save not supported on this platform"
    )


class ReachabilityResult(BaseModel):
    host: str
    port: int
    reachable: bool = Field(..., description="True if a TCP/SSH session was established")
    authenticated: bool = Field(..., description="True if the credentials were accepted")
    error: str | None = None
