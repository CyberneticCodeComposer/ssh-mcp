"""Read-only SSH tools — always registered.

Every command passes the dangerous-command denylist (safety.check_read_only)
before a connection is opened, and all device output is run through
safety.redact() before it is returned.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from ..connection import (
    SUPPORTED_PLATFORMS,
    SSHAuthError,
    SSHCommandError,
    SSHConnectError,
    execute,
    open_connection,
)
from ..safety import cap_output, check_read_only, redact, strip_terminal_noise
from ._shared import (
    CommandResult,
    MultiCommandResult,
    ReachabilityResult,
    get_settings,
    resolve_profile,
)

_PLATFORM_HINT = (
    "Platform slug — one of: " + ", ".join(SUPPORTED_PLATFORMS) + ". "
    "Use 'linux' for generic Unix/Alpine hosts."
)


def register(mcp: FastMCP) -> None:

    @mcp.tool(name="ssh_run_command")
    async def run_command(
        ctx: Context,
        host: Annotated[str, "Hostname, FQDN, or IP of the device to connect to"],
        platform: Annotated[str, _PLATFORM_HINT],
        command: Annotated[str, "A single read-only command to run, e.g. 'show interface brief'"],
        credential_profile: Annotated[str, "Name of the configured credential profile"] = "default",
        port: Annotated[int, "SSH port"] = 22,
        timeout: Annotated[
            float | None, "Per-command timeout in seconds (overrides the default)"
        ] = None,
    ) -> CommandResult:
        """Run one read-only CLI command on a network device or host over SSH.

        Use this to pull live diagnostic output — `show`/`display`/`get`
        commands on network gear, or read-only shell commands on Linux hosts.
        Do NOT use this to change configuration: state-changing commands are
        rejected by the safety denylist — use `ssh_send_config` (write mode)
        instead. For several commands on the same host, use `ssh_run_commands`
        so the connection is opened once.

        Inputs: `host` (hostname/IP), `platform` (see slug list), `command`
        (one command; it must be non-destructive). Returns the device `output`
        (credentials redacted), a `failed` flag set when the device reported
        the command as invalid, and `elapsed_seconds`. Output is returned in
        full — for very large commands (e.g. `show running-config` on a big
        switch) scope the command or apply a device-side filter (`| include`)
        when you do not need all of it."""
        settings = get_settings(ctx)
        reason = check_read_only(command, settings.denylist_extra)
        if reason:
            raise ToolError(reason)
        profile = resolve_profile(settings, credential_profile)

        async with open_connection(host, platform, profile, settings, port, timeout) as driver:
            resp = await execute(driver, command)

        return CommandResult(
            host=host,
            platform=platform,
            command=command,
            output=cap_output(redact(strip_terminal_noise(resp.result)), settings.max_output_bytes),
            failed=bool(resp.failed),
            elapsed_seconds=getattr(resp, "elapsed_time", None),
        )

    @mcp.tool(name="ssh_run_commands")
    async def run_commands(
        ctx: Context,
        host: Annotated[str, "Hostname, FQDN, or IP of the device to connect to"],
        platform: Annotated[str, _PLATFORM_HINT],
        commands: Annotated[list[str], "Read-only commands to run in order over one connection"],
        credential_profile: Annotated[str, "Name of the configured credential profile"] = "default",
        port: Annotated[int, "SSH port"] = 22,
        timeout: Annotated[float | None, "Per-command timeout in seconds"] = None,
    ) -> MultiCommandResult:
        """Run several read-only commands on one host over a single SSH session.

        Use this when collecting multiple `show`/diagnostic commands from the
        same device — it is faster and gentler on the device than repeated
        `ssh_run_command` calls. Do NOT use it for configuration changes
        (denylist-enforced) — use `ssh_send_config`.

        Inputs: `host`, `platform`, `commands` (a list; every command must be
        non-destructive — if any one is denied, the whole call is rejected
        before connecting). Returns one `CommandResult` per command and a
        top-level `failed` flag. If the SSH session drops mid-batch, that
        command's result carries `error`, the batch stops there, and the
        results gathered so far are still returned."""
        settings = get_settings(ctx)
        if not commands:
            raise ToolError("`commands` is empty — provide at least one command.")
        for cmd in commands:
            reason = check_read_only(cmd, settings.denylist_extra)
            if reason:
                raise ToolError(reason)
        profile = resolve_profile(settings, credential_profile)

        results: list[CommandResult] = []
        async with open_connection(host, platform, profile, settings, port, timeout) as driver:
            for cmd in commands:
                try:
                    resp = await execute(driver, cmd)
                except SSHCommandError as exc:
                    # Session dropped — record it and stop; keep earlier results.
                    results.append(
                        CommandResult(
                            host=host,
                            platform=platform,
                            command=cmd,
                            output="",
                            failed=True,
                            error=str(exc),
                        )
                    )
                    break
                results.append(
                    CommandResult(
                        host=host,
                        platform=platform,
                        command=cmd,
                        output=cap_output(
                            redact(strip_terminal_noise(resp.result)),
                            settings.max_output_bytes,
                        ),
                        failed=bool(resp.failed),
                        elapsed_seconds=getattr(resp, "elapsed_time", None),
                    )
                )

        return MultiCommandResult(
            host=host,
            platform=platform,
            failed=any(r.failed for r in results),
            results=results,
        )

    @mcp.tool(name="ssh_check_reachable")
    async def check_reachable(
        ctx: Context,
        host: Annotated[str, "Hostname, FQDN, or IP of the device to test"],
        port: Annotated[int, "SSH port"] = 22,
        platform: Annotated[
            str, "Platform slug — affects SSH algorithm negotiation for old gear"
        ] = "linux",
        credential_profile: Annotated[str, "Name of the configured credential profile"] = "default",
    ) -> ReachabilityResult:
        """Test whether a host is reachable over SSH and accepts the credentials.

        Use this before diagnosing further when a device may be down or
        unreachable, or to confirm a credential profile works. It opens and
        immediately closes a session — it runs no commands. Do NOT use it to
        gather device data; use `ssh_run_command` for that.

        Inputs: `host`, `port`, optional `platform` (pass the real slug when
        testing very old Cisco/ProCurve gear so legacy ciphers are offered).
        Returns `reachable` (a TCP/SSH session was established), `authenticated`
        (credentials accepted), and an `error` string when either is false."""
        settings = get_settings(ctx)
        profile = resolve_profile(settings, credential_profile)
        try:
            async with open_connection(host, platform, profile, settings, port):
                pass
        except SSHAuthError as exc:
            # The device answered on SSH — it is reachable; creds were rejected.
            return ReachabilityResult(
                host=host, port=port, reachable=True, authenticated=False, error=str(exc)
            )
        except SSHConnectError as exc:
            return ReachabilityResult(
                host=host, port=port, reachable=False, authenticated=False, error=str(exc)
            )
        # UnsupportedPlatformError is a usage error — let it propagate.
        return ReachabilityResult(host=host, port=port, reachable=True, authenticated=True)
