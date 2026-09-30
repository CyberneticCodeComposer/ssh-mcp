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
    command_policy,
    execute,
    is_unix_host,
    open_connection,
    probe_reachable,
)
from ..safety import cap_output, check_read_only, redact, strip_terminal_noise
from ._shared import (
    CommandResult,
    MultiCommandResult,
    ReachabilityResult,
    check_vdom_supported,
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
        vdom: Annotated[
            str | None,
            "FortiOS only: the device context to run in — a VDOM name, or "
            "'global'. On a multi-VDOM FortiGate most reads (`get system "
            "interface`, `get system performance status`, `get system ha "
            "status`, `get router info routing-table all`) are out of scope at "
            "the top-level prompt and fail with 'command parse error' / "
            "'Command fail. Return code -61'. The server performs the "
            "`config global` / `config vdom` + `edit <name>` navigation itself. "
            "Omit it to run at the top level (`get system status`, `show`) — "
            "or, if your MCP client cannot omit an optional parameter, pass an "
            "empty string, which means the same thing.",
        ] = None,
    ) -> CommandResult:
        """Run one read-only CLI command on a network device or host over SSH.

        Use this to pull live diagnostic output — `show`/`display`/`get`
        commands on network gear, or read-only shell commands on Linux hosts.
        Do NOT use this to change configuration: state-changing commands are
        rejected — by a dangerous-command denylist on network gear, and by a
        positive read-only allowlist on `linux`/`generic` Unix hosts (only
        known-safe read commands run there). Use `ssh_send_config` (write mode)
        for changes. For several commands on the same host, use
        `ssh_run_commands` so the connection is opened once.

        Inputs: `host` (hostname/IP), `platform` (see slug list), `command`
        (one command; it must be non-destructive). Returns the device `output`
        (credentials redacted), a `failed` flag set when the device reported
        the command as invalid, and `elapsed_seconds`. Output is returned in
        full — for very large commands (e.g. `show running-config` on a big
        switch) scope the command or apply a device-side filter (`| include`)
        when you do not need all of it."""
        settings = get_settings(ctx)
        reason = check_read_only(
            command,
            settings.denylist_extra,
            unix_host=is_unix_host(platform),
            allow_extra=settings.unix_allow_extra,
            policy=command_policy(platform),
            allow_commands=settings.allow_commands,
        )
        if reason:
            raise ToolError(reason)
        vdom = check_vdom_supported(platform, vdom)
        profile = resolve_profile(settings, credential_profile)

        async with open_connection(
            host, platform, profile, settings, port, timeout, context=vdom
        ) as driver:
            resp = await execute(driver, command)

        return CommandResult(
            host=host,
            platform=platform,
            command=command,
            output=cap_output(redact(strip_terminal_noise(resp.result)), settings.max_output_bytes),
            failed=bool(resp.failed),
            elapsed_seconds=getattr(resp, "elapsed_time", None),
            vdom=vdom,
            note=getattr(resp, "note", None),
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
        vdom: Annotated[
            str | None,
            "FortiOS only: the device context to run in — a VDOM name, or "
            "'global'. On a multi-VDOM FortiGate most reads (`get system "
            "interface`, `get system performance status`, `get system ha "
            "status`, `get router info routing-table all`) are out of scope at "
            "the top-level prompt and fail with 'command parse error' / "
            "'Command fail. Return code -61'. The server performs the "
            "`config global` / `config vdom` + `edit <name>` navigation itself. "
            "Omit it to run at the top level (`get system status`, `show`) — "
            "or, if your MCP client cannot omit an optional parameter, pass an "
            "empty string, which means the same thing.",
        ] = None,
    ) -> MultiCommandResult:
        """Run several read-only commands on one host over a single SSH session.

        Use this when collecting multiple `show`/diagnostic commands from the
        same device — it is faster and gentler on the device than repeated
        `ssh_run_command` calls. Do NOT use it for configuration changes
        (rejected by the denylist on network gear / the read-only allowlist on
        Unix hosts) — use `ssh_send_config`.

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
            reason = check_read_only(
                cmd,
                settings.denylist_extra,
                unix_host=is_unix_host(platform),
                allow_extra=settings.unix_allow_extra,
                policy=command_policy(platform),
                allow_commands=settings.allow_commands,
            )
            if reason:
                raise ToolError(reason)
        vdom = check_vdom_supported(platform, vdom)
        profile = resolve_profile(settings, credential_profile)

        results: list[CommandResult] = []
        # The context is entered once for the whole batch, by open_connection.
        async with open_connection(
            host, platform, profile, settings, port, timeout, context=vdom
        ) as driver:
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
                            vdom=vdom,
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
                        vdom=vdom,
                        note=getattr(resp, "note", None),
                    )
                )

        return MultiCommandResult(
            host=host,
            platform=platform,
            failed=any(r.failed for r in results),
            results=results,
            vdom=vdom,
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
            await probe_reachable(host, platform, profile, settings, port)
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
