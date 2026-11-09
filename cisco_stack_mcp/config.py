"""Settings, all from environment variables (systemd loads them from /etc/cisco-stack-mcp)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    return float(raw) if raw else default


@dataclass
class Settings:
    inventory_file: str = field(default_factory=lambda: os.environ.get(
        "CSM_INVENTORY", "/etc/cisco-stack-mcp/stacks.yaml"))
    ssh_username: str = field(default_factory=lambda: os.environ.get("CSM_SSH_USERNAME", "mcp-ro"))
    ssh_password: str = field(default_factory=lambda: os.environ.get("CSM_SSH_PASSWORD", ""), repr=False)
    ssh_port: int = field(default_factory=lambda: _int("CSM_SSH_PORT", 22))
    # When set, SSH host keys are verified against this file (recommended).
    known_hosts: str = field(default_factory=lambda: os.environ.get("CSM_KNOWN_HOSTS", ""))
    tokens_file: str = field(default_factory=lambda: os.environ.get(
        "CSM_TOKENS_FILE", "/etc/cisco-stack-mcp/tokens.json"))
    audit_log: str = field(default_factory=lambda: os.environ.get(
        "CSM_AUDIT_LOG", "/var/log/cisco-stack-mcp/audit.jsonl"))
    listen_host: str = field(default_factory=lambda: os.environ.get("CSM_HOST", "127.0.0.1"))
    listen_port: int = field(default_factory=lambda: _int("CSM_PORT", 8002))
    cache_ttl: float = field(default_factory=lambda: _float("CSM_CACHE_TTL", 30.0))
    idle_timeout: float = field(default_factory=lambda: _float("CSM_IDLE_TIMEOUT", 300.0))
    connect_timeout: float = field(default_factory=lambda: _float("CSM_CONNECT_TIMEOUT", 15.0))
    command_timeout: float = field(default_factory=lambda: _float("CSM_COMMAND_TIMEOUT", 60.0))
    rate_limit_per_min: int = field(default_factory=lambda: _int("CSM_RATE_LIMIT", 30))
    max_rows: int = field(default_factory=lambda: _int("CSM_MAX_ROWS", 500))
    # Only for the mock-switch tests; never set in production.
    auth_disabled: bool = field(default_factory=lambda: os.environ.get("CSM_AUTH_DISABLED", "") == "1")
