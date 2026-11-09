"""A mock IOS XE switch over SSH that replays captured command output.

Usage (standalone):  python tests/mock_switch.py core-a:2201 core-b:2202
Each stack listens on its own port and answers from tests/fixtures/<stack>/,
falling back to tests/fixtures/core-a/. Anything else gets '% Invalid input'.
"""

from __future__ import annotations

import asyncio
import os
import sys

import asyncssh

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
USERNAME, PASSWORD = "mcp-ro", "test-password"
# Commands the MCP-RO parser view would allow but which need no output.
SILENT_OK = {"terminal length 0", "terminal width 511", "terminal width 0", ""}


def fixture_name(command: str) -> str:
    return command.strip().replace("/", "_").replace(" ", "_") + ".txt"


def lookup(stack: str, command: str) -> str | None:
    if not command.startswith("show "):
        return None
    for d in (stack, "core-a"):
        path = os.path.join(FIXTURES, d, fixture_name(command))
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return fh.read()
    return None


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == USERNAME and password == PASSWORD


def make_handler(stack: str, log: list | None = None):
    prompt = f"{stack}#"

    async def handle(process: asyncssh.SSHServerProcess):
        process.stdout.write(f"\r\n{prompt}")
        try:
            while True:
                line = await process.stdin.readline()
                if line == "":
                    break
                cmd = line.strip()
                if log is not None:
                    log.append((stack, cmd))
                if cmd in SILENT_OK:
                    out = ""
                elif cmd in ("exit", "logout"):
                    break
                else:
                    text = lookup(stack, cmd)
                    out = text if text is not None else "                ^\n% Invalid input detected at '^' marker.\n"
                if out:
                    process.stdout.write(out.replace("\r\n", "\n").replace("\n", "\r\n"))
                    if not out.endswith("\n"):
                        process.stdout.write("\r\n")
                process.stdout.write(prompt)
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, ConnectionError):
            pass
        finally:
            process.exit(0)

    return handle


async def start(stacks: dict[str, int], host_key_path: str, log: list | None = None) -> list:
    if not os.path.exists(host_key_path):
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(host_key_path)
    servers = []
    for stack, port in stacks.items():
        srv = await asyncssh.create_server(
            _Server, "127.0.0.1", port, server_host_keys=[host_key_path],
            process_factory=make_handler(stack, log), line_editor=True, line_echo=True,
        )
        servers.append(srv)
    return servers


async def _main(args):
    stacks = {a.split(":")[0]: int(a.split(":")[1]) for a in args} or {"core-a": 2201, "core-b": 2202}
    key = os.path.join(os.path.dirname(__file__), ".mock_host_key")
    await start(stacks, key)
    print(f"mock switches listening: {stacks}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(_main(sys.argv[1:]))
