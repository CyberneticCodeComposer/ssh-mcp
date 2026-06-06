"""Environment-driven configuration.

Parsed once at lifespan startup into an immutable Settings object. Backend SSH
credentials are NOT validated at startup — a missing profile fails loudly on
the first tool call that needs it, with a recovery message, rather than
preventing the server from booting.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw == "":
        return default
    return raw in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class CredentialProfile:
    """One named SSH credential set. Authentication uses the password and/or
    the private key — at least one must be set."""

    name: str
    username: str = ""
    password: str = ""
    enable_secret: str = ""
    private_key: str = ""  # path to a private key file (~ is expanded)
    private_key_passphrase: str = ""  # passphrase for an encrypted private key


@dataclass(frozen=True)
class Settings:
    write_enabled: bool
    credentials: dict[str, CredentialProfile]
    known_hosts: str | None
    timeout_socket: float
    timeout_ops: float
    denylist_extra: list[str] = field(default_factory=list)
    mcp_auth_token: str = ""
    # Host-key verification: "tofu" (accept-new, default), "strict", or "off".
    host_key_policy: str = "tofu"
    # Optional connection allowlist (host globs / CIDRs); empty = allow all.
    allowed_hosts: list[str] = field(default_factory=list)
    # Cap on returned device output in bytes; 0 disables the cap.
    max_output_bytes: int = 1_000_000
    # Audit-log destination: a file path or 'stderr'; None disables auditing.
    audit_log: str | None = None

    def get_profile(self, name: str) -> CredentialProfile:
        """Return a credential profile or raise a ToolError-friendly ValueError."""
        profile = self.credentials.get(name)
        if profile is None:
            available = ", ".join(sorted(self.credentials)) or "(none configured)"
            raise ValueError(
                f"SSH credential profile '{name}' is not configured. "
                f"Available profiles: {available}. Set SSH_MCP_CREDENTIALS (JSON) "
                f"or SSH_MCP_USERNAME/SSH_MCP_PASSWORD for the 'default' profile."
            )
        if not profile.username:
            raise ValueError(
                f"SSH credential profile '{name}' has no username. "
                f"Fix SSH_MCP_CREDENTIALS or the SSH_MCP_USERNAME env var."
            )
        if not profile.password and not profile.private_key:
            raise ValueError(
                f"SSH credential profile '{name}' has no authentication method — "
                f"set a password and/or a private key. For the 'default' profile "
                f"use SSH_MCP_PASSWORD and/or SSH_MCP_PRIVATE_KEY."
            )
        return profile


def _load_credentials() -> dict[str, CredentialProfile]:
    """Build credential profiles from SSH_MCP_CREDENTIALS (JSON) plus the
    SSH_MCP_USERNAME/PASSWORD/ENABLE_SECRET/PRIVATE_KEY/PRIVATE_KEY_PASSPHRASE
    shorthand for the 'default' profile."""
    profiles: dict[str, CredentialProfile] = {}

    raw = os.environ.get("SSH_MCP_CREDENTIALS", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"SSH_MCP_CREDENTIALS is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("SSH_MCP_CREDENTIALS must be a JSON object of named profiles.")
        for pname, body in parsed.items():
            if not isinstance(body, dict):
                raise ValueError(f"SSH_MCP_CREDENTIALS['{pname}'] must be a JSON object.")
            profiles[pname] = CredentialProfile(
                name=pname,
                username=str(body.get("username", "")),
                password=str(body.get("password", "")),
                enable_secret=str(body.get("enable_secret", "")),
                private_key=str(body.get("private_key", "")),
                private_key_passphrase=str(body.get("private_key_passphrase", "")),
            )

    # Shorthand fills the 'default' profile only when JSON didn't already define it.
    short_user = os.environ.get("SSH_MCP_USERNAME", "").strip()
    if short_user and "default" not in profiles:
        profiles["default"] = CredentialProfile(
            name="default",
            username=short_user,
            password=os.environ.get("SSH_MCP_PASSWORD", ""),
            enable_secret=os.environ.get("SSH_MCP_ENABLE_SECRET", ""),
            private_key=os.environ.get("SSH_MCP_PRIVATE_KEY", "").strip(),
            private_key_passphrase=os.environ.get("SSH_MCP_PRIVATE_KEY_PASSPHRASE", ""),
        )

    return profiles


def load_settings() -> Settings:
    extra = [
        p.strip() for p in os.environ.get("SSH_MCP_DENYLIST_EXTRA", "").split(",") if p.strip()
    ]
    known_hosts = os.environ.get("SSH_MCP_KNOWN_HOSTS", "").strip() or None
    policy = os.environ.get("SSH_MCP_HOST_KEY_POLICY", "").strip().lower() or "tofu"
    if policy not in ("tofu", "strict", "off"):
        policy = "tofu"
    allowed_hosts = [
        h.strip() for h in os.environ.get("SSH_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()
    ]
    return Settings(
        write_enabled=_env_bool("SSH_MCP_ENABLE_WRITE", False),
        credentials=_load_credentials(),
        known_hosts=known_hosts,
        timeout_socket=_env_float("SSH_MCP_TIMEOUT_SOCKET", 15.0),
        timeout_ops=_env_float("SSH_MCP_TIMEOUT_OPS", 30.0),
        denylist_extra=extra,
        mcp_auth_token=os.environ.get("SSH_MCP_MCP_AUTH_TOKEN", "").strip(),
        host_key_policy=policy,
        allowed_hosts=allowed_hosts,
        max_output_bytes=_env_int("SSH_MCP_MAX_OUTPUT_BYTES", 1_000_000),
        audit_log=os.environ.get("SSH_MCP_AUDIT_LOG", "").strip() or None,
    )
