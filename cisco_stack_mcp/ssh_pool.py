"""SSH sessions to each stack: one session and one in-flight command per stack."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .commands import assert_allowed
from .config import Settings
from .inventory import Stack

log = logging.getLogger("cisco_stack_mcp.ssh")

_REJECTION_MARKERS = (
    "% invalid input",
    "% authorization failed",
    "command authorization failed",
    "% unrecognized command",
    "% incomplete command",
    "% ambiguous command",
    "% this command is not authorized",
    "% permission denied",
)


class SwitchError(RuntimeError):
    """Base class for errors talking to a switch."""


class SwitchUnreachable(SwitchError):
    pass


class CommandRejected(SwitchError):
    """The switch refused the command (usually: not in the MCP-RO parser view)."""


def _check_rejection(command: str, output: str) -> None:
    head = [ln.strip().lower() for ln in output.splitlines() if ln.strip()][:4]
    for line in head:
        for marker in _REJECTION_MARKERS:
            if line.startswith(marker) or marker in line[:60]:
                raise CommandRejected(
                    f"switch rejected '{command}': {line}. "
                    "Check the MCP-RO parser view includes this command."
                )


@dataclass
class _Session:
    conn: object | None = None
    last_used: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class SSHRunner:
    """Runs allowlisted commands over Netmiko, with a per-stack lock and a short cache."""

    def __init__(self, settings: Settings, connect_factory=None):
        self.settings = settings
        self._sessions: dict[str, _Session] = {}
        self._cache: dict[tuple[str, str], tuple[float, str]] = {}
        self._connect_factory = connect_factory or self._netmiko_connect
        self._reaper: asyncio.Task | None = None

    # -- connection management ------------------------------------------------

    def _netmiko_connect(self, stack: Stack):
        from netmiko import ConnectHandler  # imported lazily: heavy

        params = dict(
            device_type="cisco_xe",
            host=stack.host,
            port=stack.port or self.settings.ssh_port,
            username=self.settings.ssh_username,
            password=self.settings.ssh_password,
            conn_timeout=self.settings.connect_timeout,
            auth_timeout=self.settings.connect_timeout,
            banner_timeout=self.settings.connect_timeout,
            read_timeout_override=self.settings.command_timeout,
            allow_agent=False,
            use_keys=False,
            fast_cli=False,
        )
        if self.settings.known_hosts:
            params.update(ssh_strict=True, system_host_keys=False,
                          alt_host_keys=True, alt_key_file=self.settings.known_hosts)
        else:
            params.update(ssh_strict=False)
        return ConnectHandler(**params)

    def _session(self, name: str) -> _Session:
        if name not in self._sessions:
            self._sessions[name] = _Session()
        return self._sessions[name]

    @staticmethod
    def _close(conn) -> None:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - best effort
            pass

    def start_reaper(self) -> None:
        if self._reaper is None or self._reaper.done():
            self._reaper = asyncio.create_task(self._reap_loop())

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            await self.close_idle()

    async def close_idle(self) -> None:
        now = time.monotonic()
        for name, sess in list(self._sessions.items()):
            if sess.conn is not None and not sess.lock.locked() \
                    and now - sess.last_used > self.settings.idle_timeout:
                async with sess.lock:
                    conn, sess.conn = sess.conn, None
                if conn is not None:
                    log.info("closing idle session to %s", name)
                    await asyncio.to_thread(self._close, conn)

    async def close_all(self) -> None:
        if self._reaper:
            self._reaper.cancel()
        for sess in self._sessions.values():
            if sess.conn is not None:
                await asyncio.to_thread(self._close, sess.conn)
                sess.conn = None

    # -- command execution ----------------------------------------------------

    async def run(self, stack: Stack, command: str, use_cache: bool = True) -> dict:
        """Run one allowlisted command. Returns {'output', 'cached', 'duration_ms'}."""
        assert_allowed(command)
        key = (stack.name, command)
        now = time.monotonic()
        if use_cache and key in self._cache:
            ts, output = self._cache[key]
            if now - ts < self.settings.cache_ttl:
                return {"output": output, "cached": True, "duration_ms": 0}

        sess = self._session(stack.name)
        async with sess.lock:
            started = time.monotonic()
            output = await self._run_locked(stack, sess, command)
            sess.last_used = time.monotonic()
        _check_rejection(command, output)
        self._cache[key] = (time.monotonic(), output)
        return {"output": output, "cached": False,
                "duration_ms": int((time.monotonic() - started) * 1000)}

    async def _run_locked(self, stack: Stack, sess: _Session, command: str) -> str:
        for attempt in (1, 2):
            if sess.conn is None:
                try:
                    sess.conn = await asyncio.to_thread(self._connect_factory, stack)
                except Exception as exc:  # noqa: BLE001
                    raise SwitchUnreachable(
                        f"cannot open SSH session to {stack.name} ({stack.host}): {type(exc).__name__}: {exc}"
                    ) from exc
            try:
                return await asyncio.to_thread(
                    sess.conn.send_command, command,
                    read_timeout=self.settings.command_timeout,
                    strip_prompt=True, strip_command=True,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("command on %s failed (attempt %d): %s", stack.name, attempt, exc)
                conn, sess.conn = sess.conn, None
                await asyncio.to_thread(self._close, conn)
                if attempt == 2:
                    raise SwitchUnreachable(
                        f"command '{command}' on {stack.name} failed: {type(exc).__name__}: {exc}"
                    ) from exc
        raise SwitchUnreachable("unreachable")  # pragma: no cover
