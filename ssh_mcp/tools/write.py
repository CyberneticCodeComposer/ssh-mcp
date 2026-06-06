"""Write-mode SSH tool — registered ONLY when SSH_MCP_ENABLE_WRITE is true.

When write mode is off this module's `register()` is never called, so the agent
cannot see or invoke `ssh_send_config`. When on, the tool still requires an
explicit `confirm="yes"` argument per call.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from ..connection import (
    SAVE_COMMANDS,
    SUPPORTED_PLATFORMS,
    SSHCommandError,
    execute,
    execute_configs,
    is_generic,
    normalize_platform,
    open_connection,
)
from ..safety import cap_output, redact, strip_terminal_noise
from ._shared import ConfigResult, get_settings, resolve_profile

_PLATFORM_HINT = (
    "Platform slug — one of: " + ", ".join(SUPPORTED_PLATFORMS) + ". "
    "Use 'linux' for generic Unix/Alpine hosts."
)


def register(mcp: FastMCP) -> None:

    @mcp.tool(name="ssh_send_config")
    async def send_config(
        ctx: Context,
        host: Annotated[str, "Hostname, FQDN, or IP of the device to configure"],
        platform: Annotated[str, _PLATFORM_HINT],
        config_commands: Annotated[list[str], "Config-mode commands to apply, in order"],
        confirm: Annotated[Literal["yes"], "Must be the literal 'yes' — this changes device state"],
        save: Annotated[bool, "Persist running-config to startup after a successful apply"] = False,
        credential_profile: Annotated[str, "Name of the configured credential profile"] = "default",
        port: Annotated[int, "SSH port"] = 22,
        timeout: Annotated[float | None, "Per-command timeout in seconds"] = None,
    ) -> ConfigResult:
        """Apply configuration changes to a device over SSH (write mode).

        Use this only to make intended configuration changes. On network
        platforms it enters config mode, sends each command, and exits — which
        structurally prevents exec-level destructive commands (`reload`,
        `erase`) from running through this tool. On 'linux'/'generic' hosts
        there is no config mode, so the commands run directly in the shell.
        Do NOT use this for diagnostics — use the read tools, which are safer
        and always available.

        This tool exists only because an operator set SSH_MCP_ENABLE_WRITE=true.
        It stops at the first command the device rejects. For Junos / IOS-XR,
        include an explicit `commit` as the last config command. If the SSH
        session drops mid-apply on a generic/shell platform, it returns a
        partial result — `failed=True` with a `note` saying how many commands
        were sent — so you can see how far the apply got.

        Inputs: `host`, `platform`, `config_commands` (list, applied in order),
        `confirm` (must be the literal `"yes"`), optional `save` (writes
        startup-config on success). Returns the per-command `output`
        (credentials redacted), a `failed` flag, and `saved`."""
        if confirm != "yes":
            raise ToolError(
                "Refusing to apply configuration without confirm='yes'. "
                'Pass confirm="yes" to acknowledge this changes device state.'
            )
        settings = get_settings(ctx)
        if not settings.write_enabled:  # defence in depth — tool shouldn't be registered
            raise ToolError("Write mode is disabled (SSH_MCP_ENABLE_WRITE is not true).")
        if not config_commands:
            raise ToolError("`config_commands` is empty — provide at least one command.")
        profile = resolve_profile(settings, credential_profile)
        slug = normalize_platform(platform)

        drop_note: str | None = None
        async with open_connection(host, platform, profile, settings, port, timeout) as driver:
            if is_generic(platform):
                # Heterogeneous: scrapli Response on the generic-driver path,
                # ShellResponse on the raw-shell path. Both duck-type the same.
                responses: list = []
                for cmd in config_commands:
                    try:
                        resp = await execute(driver, cmd)
                    except SSHCommandError as exc:
                        # Session dropped mid-apply — the device may be left
                        # partially configured. Stop and report how far the
                        # apply got, rather than erroring with no result.
                        drop_note = (
                            f"SSH session dropped while applying {redact(cmd)!r}; "
                            f"{len(responses)} of {len(config_commands)} commands "
                            f"were sent before the drop. The device may be "
                            f"partially configured — inspect it before retrying. "
                            f"({exc})"
                        )
                        break
                    responses.append(resp)
                    if resp.failed:
                        break
            else:
                responses = await execute_configs(driver, list(config_commands))

            failed = bool(drop_note) or any(bool(r.failed) for r in responses)

            saved = False
            note: str | None = drop_note
            if save and not failed:
                save_cmd = SAVE_COMMANDS.get(slug)
                if is_generic(platform):
                    note = "save is not applicable to generic/linux hosts; ignored."
                elif save_cmd is None:
                    note = (
                        f"save not supported for platform '{platform}'. "
                        f"For Junos/IOS-XR, include 'commit' in config_commands."
                    )
                else:
                    save_resp = await execute(driver, save_cmd)
                    saved = not bool(save_resp.failed)
                    if not saved:
                        note = f"running config applied but '{save_cmd}' failed."

        output = cap_output(
            redact(
                strip_terminal_noise(
                    "\n".join(
                        f"=== {getattr(r, 'channel_input', '')} ===\n{r.result}" for r in responses
                    )
                )
            ),
            settings.max_output_bytes,
        )
        return ConfigResult(
            host=host,
            platform=platform,
            # Echo the commands back redacted — a config line may carry a
            # credential and the result could be logged downstream.
            commands=[redact(c) for c in config_commands],
            output=output,
            failed=failed,
            saved=saved,
            note=note,
        )
