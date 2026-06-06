"""Scrapli connection factory.

Maps the server's stable platform slugs to scrapli drivers, applies a
legacy SSH-algorithm profile for old gear (Catalyst IOS 12.x, ProCurve), and
opens connections via the asyncssh transport. Connections are per-call: open,
run, close — there is no pool.

Design lessons carried from a prior Go SSH collector:
  - legacy CBC ciphers / dh-group1 kex are required by old IOS and ProCurve;
  - host-key verification is opt-in (a known_hosts path) and otherwise off.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any

import asyncssh
from fastmcp.exceptions import ToolError

from .hostkeys import (
    ensure_known_hosts_file,
    make_tofu_client_factory,
    resolve_known_hosts_path,
)
from .safety import check_host_allowed, redact
from .settings import CredentialProfile, Settings
from .shell import ShellConnection, open_shell

# --- typed errors ---------------------------------------------------------


class SSHError(ToolError):
    """Base class for SSH failures. Subclasses ToolError so the recovery
    message reaches the agent without per-tool translation; tools that need to
    branch on the failure kind (ssh_check_reachable) catch the subclasses."""


class SSHAuthError(SSHError):
    """The device answered on SSH but rejected the supplied credentials."""


class SSHConnectError(SSHError):
    """No TCP/SSH session could be established — host unreachable, SSH not
    listening, a timeout, or an algorithm mismatch with very old gear."""


class SSHCommandError(SSHError):
    """A command failed at the transport level — the SSH session dropped or
    timed out mid-command. Distinct from the device rejecting a command, which
    is reported as failed=True on the result without raising."""


class UnsupportedPlatformError(SSHError):
    """The platform slug is not recognised."""


# --- platform mapping -----------------------------------------------------

# slug -> scrapli network platform string (resolved by the AsyncScrapli factory,
# which consults both scrapli core and scrapli-community).
_NETWORK_PLATFORMS: dict[str, str] = {
    "cisco-ios": "cisco_iosxe",
    "cisco-iosxe": "cisco_iosxe",
    "cisco-nxos": "cisco_nxos",
    "cisco-iosxr": "cisco_iosxr",
    "arista-eos": "arista_eos",
    "juniper-junos": "juniper_junos",
    "aruba-cx": "aruba_aoscx",
    "vyos": "vyos_vyos",
    "fortios": "fortinet_fortios",
    "fortinet": "fortinet_fortios",
    "paloalto-panos": "paloalto_panos",
    "huawei-vrp": "huawei_vrp",
}

# slugs handled by the scrapli generic driver (plain interactive shell, no
# paging/privilege concepts) — Linux/Alpine hosts. ArubaOS-Switch (ProCurve)
# and ArubaOS Mobility Controllers are listed here so is_generic() and the
# write tool treat them as no-config-mode hosts, but they are actually
# connected via a raw PTY shell, not scrapli — see _SHELL_PLATFORMS / shell.py.
_GENERIC_PLATFORMS: set[str] = {"linux", "generic", "aruba-os-switch", "aruba-os"}

# Platforms whose SSH stacks need legacy ciphers / key exchange / host-key algs.
_LEGACY_PLATFORMS: set[str] = {"cisco-ios", "cisco-iosxe", "aruba-os-switch"}

# Platforms driven by a raw asyncssh PTY shell (shell.py) instead of scrapli.
# ArubaOS-Switch (ProCurve) and ArubaOS Mobility Controllers present an
# interactive CLI — a login banner, a pager, and a prompt scrapli cannot
# detect — that stalls scrapli's prompt detection during connection open
# ("timed out getting prompt"); a post-open drain can never help because the
# open itself fails. shell.py opens a PTY, dismisses + drains the banner,
# disables paging, and reads by quiet-time detection. These slugs stay in
# _GENERIC_PLATFORMS too, so is_generic() / SUPPORTED_PLATFORMS / the write
# tool keep treating them as no-config-mode hosts.
_SHELL_PLATFORMS: set[str] = {"aruba-os-switch", "aruba-os"}

# Pager-disable command for each shell platform, sent once after the banner
# drain so long `show` output is not chopped at a "-- MORE --" prompt.
_PAGING_COMMANDS: dict[str, str] = {
    "aruba-os-switch": "no page",  # ProCurve / ArubaOS-Switch
    "aruba-os": "no paging",  # ArubaOS Mobility Controller / Conductor
}

# Exec-mode command that persists running-config to startup, by slug. Used by
# the write tool's optional `save` flag. Junos / IOS-XR / PAN-OS persist via
# `commit` inside the config session, and Huawei `save` is interactive — all
# deliberately absent here.
SAVE_COMMANDS: dict[str, str] = {
    "cisco-ios": "write memory",
    "cisco-iosxe": "write memory",
    "cisco-nxos": "copy running-config startup-config",
    "arista-eos": "write memory",
    "aruba-cx": "write memory",
}

SUPPORTED_PLATFORMS: list[str] = sorted(_NETWORK_PLATFORMS) + sorted(_GENERIC_PLATFORMS)

# asyncssh connect kwargs that re-enable legacy algorithms. The `+` prefix
# appends to asyncssh's modern defaults instead of replacing them, so modern
# devices still negotiate their strongest mutual algorithm.
_LEGACY_ASYNCSSH: dict[str, str] = {
    "encryption_algs": "+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
    "kex_algs": "+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,"
    "diffie-hellman-group-exchange-sha1",
    "server_host_key_algs": "+ssh-rsa,ssh-dss",
    "mac_algs": "+hmac-sha1,hmac-sha1-96",
}


def normalize_platform(platform: str) -> str:
    return platform.strip().lower()


def is_generic(platform: str) -> bool:
    return normalize_platform(platform) in _GENERIC_PLATFORMS


def _resolve_key_path(profile: CredentialProfile) -> str:
    """Expand and existence-check a credential profile's private key path,
    raising a recovery-oriented ToolError when the file is missing."""
    key_path = os.path.expanduser(profile.private_key)
    if not os.path.isfile(key_path):
        raise ToolError(
            f"SSH private key file not found: {key_path!r} (credential "
            f"profile {profile.name!r}). Check the SSH_MCP_PRIVATE_KEY path "
            f"(or the profile's private_key) — it must point at a readable "
            f"private key file."
        )
    return key_path


def _asyncssh_connect_opts(
    slug: str, profile: CredentialProfile, settings: Settings
) -> dict[str, Any]:
    """asyncssh connect kwargs shared by scrapli's asyncssh transport and the
    raw-shell path: legacy algorithms, host-key verification, key passphrase.

    Host-key verification runs entirely through asyncssh (scrapli's own
    auth_strict_key pre-check is bypassed) so there is one coherent path."""
    opts: dict[str, Any] = {}
    if slug in _LEGACY_PLATFORMS:
        opts.update(_LEGACY_ASYNCSSH)

    policy = settings.host_key_policy
    if policy == "off":
        opts["known_hosts"] = None
    else:
        kh_path = resolve_known_hosts_path(settings.known_hosts)
        if policy == "strict":
            if not os.path.isfile(kh_path):
                raise ToolError(
                    f"Host-key policy is 'strict' but the known_hosts file "
                    f"{kh_path!r} does not exist. Populate it, or set "
                    f"SSH_MCP_HOST_KEY_POLICY=tofu (accept-new) or =off."
                )
            opts["known_hosts"] = kh_path
        else:  # tofu — accept-new, pinning unseen keys to kh_path
            ensure_known_hosts_file(kh_path)
            opts["known_hosts"] = kh_path
            opts["client_factory"] = make_tofu_client_factory(kh_path)

    if profile.private_key and profile.private_key_passphrase:
        opts["passphrase"] = profile.private_key_passphrase
    return opts


def _build_driver(
    host: str,
    platform: str,
    profile: CredentialProfile,
    settings: Settings,
    port: int,
    timeout_ops: float,
):
    """Construct (but do not open) the scrapli driver for a host."""
    slug = normalize_platform(platform)
    asyncssh_opts = _asyncssh_connect_opts(slug, profile, settings)

    common: dict[str, Any] = {
        "host": host,
        "port": port,
        "auth_username": profile.username,
        "auth_strict_key": False,
        "transport": "asyncssh",
        "timeout_socket": settings.timeout_socket,
        # Transport read timeout must cover a whole operation, else a long
        # `show tech-support` is cut off mid-stream.
        "timeout_transport": max(timeout_ops, settings.timeout_socket),
        "timeout_ops": timeout_ops,
    }
    if profile.password:
        common["auth_password"] = profile.password
    if profile.private_key:
        common["auth_private_key"] = _resolve_key_path(profile)

    if asyncssh_opts:
        common["transport_options"] = {"asyncssh": asyncssh_opts}

    if slug in _GENERIC_PLATFORMS:
        from scrapli.driver.generic import AsyncGenericDriver

        return AsyncGenericDriver(**common)

    if slug in _NETWORK_PLATFORMS:
        from scrapli import AsyncScrapli

        if profile.enable_secret:
            common["auth_secondary"] = profile.enable_secret
        return AsyncScrapli(platform=_NETWORK_PLATFORMS[slug], **common)

    raise UnsupportedPlatformError(
        f"Unsupported platform {platform!r}. Supported platform slugs: "
        f"{', '.join(SUPPORTED_PLATFORMS)}. Use 'linux' for generic Unix hosts."
    )


async def _open_raw_shell(
    host: str,
    slug: str,
    profile: CredentialProfile,
    settings: Settings,
    port: int,
    command_timeout: float,
) -> ShellConnection:
    """Open a raw asyncssh PTY shell (shell.py) for a banner-bearing platform,
    translating asyncssh failures into the typed SSH errors."""
    client_keys = [_resolve_key_path(profile)] if profile.private_key else None
    asyncssh_opts = _asyncssh_connect_opts(slug, profile, settings)
    try:
        return await open_shell(
            host=host,
            port=port,
            username=profile.username,
            password=profile.password,
            client_keys=client_keys,
            asyncssh_opts=asyncssh_opts,
            connect_timeout=settings.timeout_socket,
            command_timeout=command_timeout,
            paging_command=_PAGING_COMMANDS.get(slug, "no page"),
        )
    except asyncssh.PermissionDenied as exc:
        raise SSHAuthError(
            f"SSH authentication failed for {host} (profile {profile.name!r}): "
            f"{exc}. Verify the username/password or key for this credential "
            f"profile, then retry."
        ) from exc
    except (TimeoutError, asyncssh.Error, OSError) as exc:
        raise SSHConnectError(
            f"Could not connect to {host}:{port} as platform {slug!r}: {exc}. "
            f"Common causes: host unreachable, SSH not listening, or an "
            f"algorithm mismatch with very old gear. Try ssh_check_reachable "
            f"first, and confirm the platform slug."
        ) from exc


@asynccontextmanager
async def open_connection(
    host: str,
    platform: str,
    profile: CredentialProfile,
    settings: Settings,
    port: int = 22,
    timeout_ops: float | None = None,
) -> AsyncIterator[object]:
    """Open an SSH connection, yield the driver, and always close it.

    Banner-bearing platforms (_SHELL_PLATFORMS) are driven by a raw asyncssh
    PTY shell; everything else uses scrapli. Raises UnsupportedPlatformError
    for a bad slug, SSHAuthError when the device rejects credentials, and
    SSHConnectError when no session can be established — all subclass ToolError,
    so their recovery-oriented messages reach the agent directly."""
    denied = check_host_allowed(host, settings.allowed_hosts)
    if denied:
        raise ToolError(denied)

    slug = normalize_platform(platform)
    ops_timeout = timeout_ops if timeout_ops is not None else settings.timeout_ops

    # ArubaOS-Switch (ProCurve): a raw PTY shell — scrapli's prompt detection
    # cannot get past the interactive login banner. See shell.py.
    if slug in _SHELL_PLATFORMS:
        shell = await _open_raw_shell(host, slug, profile, settings, port, ops_timeout)
        try:
            yield shell
        finally:
            # Close failures must not mask the call's result.
            with suppress(Exception):
                await shell.close()
        return

    driver = _build_driver(
        host=host,
        platform=platform,
        profile=profile,
        settings=settings,
        port=port,
        timeout_ops=ops_timeout,
    )

    # Import lazily so a missing optional dep surfaces only when used.
    from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliException

    try:
        await driver.open()
    except ScrapliAuthenticationFailed as exc:
        raise SSHAuthError(
            f"SSH authentication failed for {host} (profile {profile.name!r}): {exc}. "
            f"Common causes: wrong username/password, the device needs an enable "
            f"secret (set enable_secret on the credential profile), or the account "
            f"is not authorized. Verify credentials, then retry."
        ) from exc
    except (TimeoutError, ScrapliException, OSError) as exc:
        raise SSHConnectError(
            f"Could not connect to {host}:{port} as platform {platform!r}: {exc}. "
            f"Common causes: host unreachable, SSH not listening, wrong platform "
            f"slug, or an algorithm mismatch with very old gear. Try "
            f"ssh_check_reachable first, and confirm the platform slug."
        ) from exc

    try:
        yield driver
    finally:
        # Close failures must not mask the call's result.
        with suppress(Exception):
            await driver.close()


async def execute(driver: object, command: str):
    """Run one command on an already-open driver, translating scrapli
    transport failures into SSHCommandError. A device that *rejects* a command
    does not raise — that surfaces as `failed=True` on the returned response."""
    from scrapli.exceptions import ScrapliException

    try:
        return await driver.send_command(command)  # type: ignore[attr-defined]
    except (TimeoutError, ScrapliException, OSError) as exc:
        # Redact the command/exception — a write-mode config command can carry
        # a credential, and it must not leak into an error string.
        raise SSHCommandError(
            f"SSH session failed while running {redact(command)!r}: "
            f"{redact(str(exc))}. The connection likely dropped mid-session "
            f"(common on old IOS after large output). Retry the command; if it "
            f"persists, check the device with ssh_check_reachable."
        ) from exc


async def execute_configs(driver: object, commands: list[str]):
    """Apply config-mode commands on an open network driver, translating
    scrapli transport failures into SSHCommandError. Returns the per-command
    response list (config mode is entered and exited by scrapli)."""
    from scrapli.exceptions import ScrapliException

    try:
        multi = await driver.send_configs(commands, stop_on_failed=True)  # type: ignore[attr-defined]
        return list(multi)
    except (TimeoutError, ScrapliException, OSError) as exc:
        raise SSHCommandError(
            f"SSH session failed while applying configuration: "
            f"{redact(str(exc))}. The session may have dropped mid-apply — the "
            f"device could be partially configured. Inspect it before retrying."
        ) from exc
