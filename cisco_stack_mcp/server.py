"""MCP server: read-only tools for Cisco Catalyst 9300 stacks, Streamable HTTP at /mcp."""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import __version__
from .audit import AuditLog
from .auth import BearerAuthMiddleware, RateLimiter, TokenStore
from .config import Settings
from .inventory import Inventory
from .ssh_pool import SSHRunner
from .tools import StackTools

log = logging.getLogger("cisco_stack_mcp")

INSTRUCTIONS = """Read-only access to Cisco Catalyst 9300 switch stacks (IOS XE).
Every tool takes `stack`: a name from list_stacks, or 'all'. Nothing here can change a switch.
Start with stack_summary for 'is everything healthy?'. Use find_mac to locate a device,
get_interfaces / get_interface_detail / get_interface_errors for port questions, get_stack_members
for stack health and redundancy, get_logs for recent events. Results are parsed JSON; when a
command could not be parsed a 'raw' field holds the switch output."""

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def build(settings: Settings | None = None, inventory: Inventory | None = None,
          runner: SSHRunner | None = None) -> tuple[FastMCP, StackTools]:
    settings = settings or Settings()
    inventory = inventory or Inventory.load(settings.inventory_file)
    runner = runner or SSHRunner(settings)
    tools = StackTools(settings, inventory, runner, AuditLog(settings.audit_log),
                       RateLimiter(settings.rate_limit_per_min))

    @contextlib.asynccontextmanager
    async def lifespan(_server):
        runner.start_reaper()
        try:
            yield {}
        finally:
            await runner.close_all()

    mcp = FastMCP(
        "cisco-stack-mcp",
        instructions=INSTRUCTIONS,
        host=settings.listen_host,
        port=settings.listen_port,
        stateless_http=True,
        json_response=True,
        lifespan=lifespan,
        # nginx in front sets Host to the public name; auth is by bearer token.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    names = ", ".join(inventory.names())

    @mcp.tool(annotations=RO)
    async def list_stacks() -> dict:
        """List the configured switch stacks (name, management IP, site, expected members) and the allowed command set."""
        return await tools.run_tool("list_stacks", None, tools.list_stacks)

    @mcp.tool(annotations=RO, description=(
        f"Check SSH reachability and login to a stack ({names} or 'all'); returns latency and the switch clock."))
    async def health_check(stack: str = "all") -> dict:
        return await tools.run_tool("health_check", stack, tools.health_check)

    @mcp.tool(annotations=RO)
    async def stack_summary(stack: str = "all") -> dict:
        """One-call health overview: members and roles, interface status counts, ports with errors, environment, recent severe log messages, and a list of issues."""
        return await tools.run_tool("stack_summary", stack, tools.stack_summary)

    @mcp.tool(annotations=RO)
    async def get_stack_members(stack: str = "all") -> dict:
        """Stack members (role, priority, MAC, state), stack-port cabling status and SSO redundancy state. Flags missing members, down stack ports and a missing hot standby."""
        return await tools.run_tool("get_stack_members", stack, tools.get_stack_members)

    @mcp.tool(annotations=RO)
    async def get_stack_power(stack: str = "all") -> dict:
        """StackPower budget per power stack (total, reserved, allocated and unused watts)."""
        return await tools.run_tool("get_stack_power", stack, tools.get_stack_power)

    @mcp.tool(annotations=RO)
    async def get_version(stack: str = "all") -> dict:
        """IOS XE version, uptime, last reload reason, member models and serials, and install-mode package state."""
        return await tools.run_tool("get_version", stack, tools.get_version)

    @mcp.tool(annotations=RO)
    async def get_inventory(stack: str = "all") -> dict:
        """Hardware inventory (chassis, power supplies, network modules, SFPs with PIDs and serials) and licence usage. Serials can be cross-checked with DCIM."""
        return await tools.run_tool("get_inventory", stack, tools.get_inventory)

    @mcp.tool(annotations=RO)
    async def get_environment(stack: str = "all") -> dict:
        """Fans, temperatures (with thresholds), power supplies and RPS per member, plus any sensor not in a healthy state."""
        return await tools.run_tool("get_environment", stack, tools.get_environment)

    @mcp.tool(annotations=RO)
    async def get_interfaces(stack: str = "all", member: int | None = None, status: str | None = None,
                             vlan: str | None = None, include_l3: bool = False) -> dict:
        """Interface status table. Optional filters: member (switch number 1-8), status (connected, notconnect, err-disabled, disabled), vlan (number or 'trunk'). include_l3 adds SVI/IP interfaces."""
        return await tools.run_tool("get_interfaces", stack, tools.get_interfaces, member=member,
                                    status=status, vlan=vlan, include_l3=include_l3)

    @mcp.tool(annotations=RO)
    async def get_interface_detail(stack: str, interface: str) -> dict:
        """Full counters, rates, errors, description and switchport (mode, VLANs) for one interface, e.g. Gi1/0/14, Te2/1/1, Po10."""
        return await tools.run_tool("get_interface_detail", stack, tools.get_interface_detail, interface=interface)

    @mcp.tool(annotations=RO)
    async def get_interface_errors(stack: str = "all", nonzero_only: bool = True) -> dict:
        """Per-port error counters (FCS, align, runts, giants, collisions, discards). By default only ports with a non-zero counter."""
        return await tools.run_tool("get_interface_errors", stack, tools.get_interface_errors, nonzero_only=nonzero_only)

    @mcp.tool(annotations=RO)
    async def get_transceivers(stack: str = "all") -> dict:
        """Optical diagnostics for SFP/SFP+ uplinks: temperature, voltage, current, Tx/Rx dBm and any warning or alarm flags."""
        return await tools.run_tool("get_transceivers", stack, tools.get_transceivers)

    @mcp.tool(annotations=RO)
    async def get_vlans(stack: str = "all", include_reserved: bool = False) -> dict:
        """VLANs with their access ports, and trunks with native, allowed, active and forwarding VLAN lists."""
        return await tools.run_tool("get_vlans", stack, tools.get_vlans, include_reserved=include_reserved)

    @mcp.tool(annotations=RO)
    async def find_mac(stack: str = "all", mac: str | None = None, vlan: int | None = None,
                       interface: str | None = None, include_static: bool = False) -> dict:
        """Find where a device is connected: MAC address table filtered by mac (any common format), vlan and/or interface. With stack='all' searches every stack."""
        return await tools.run_tool("find_mac", stack, tools.find_mac, mac=mac, vlan=vlan,
                                    interface=interface, include_static=include_static)

    @mcp.tool(annotations=RO)
    async def get_neighbors(stack: str = "all", protocol: Literal["cdp", "lldp", "both"] = "both") -> dict:
        """CDP and/or LLDP neighbours: remote device, platform, ports and management address."""
        return await tools.run_tool("get_neighbors", stack, tools.get_neighbors, protocol=protocol)

    @mcp.tool(annotations=RO)
    async def get_spanning_tree(stack: str = "all") -> dict:
        """Spanning-tree mode, VLANs this stack is root for, per-VLAN port states (blocking count) and root bridge/port per VLAN."""
        return await tools.run_tool("get_spanning_tree", stack, tools.get_spanning_tree)

    @mcp.tool(annotations=RO)
    async def get_etherchannels(stack: str = "all") -> dict:
        """EtherChannel / port-channel bundles, protocol and member state, with any bundle or member not in use."""
        return await tools.run_tool("get_etherchannels", stack, tools.get_etherchannels)

    @mcp.tool(annotations=RO)
    async def get_logs(stack: str = "all", lines: int = 100, max_severity: int = 7,
                       contains: str | None = None) -> dict:
        """Recent syslog buffer messages, newest last. max_severity 0-7 (3 = errors and worse, 4 = warnings and worse); contains filters by text."""
        return await tools.run_tool("get_logs", stack, tools.get_logs, lines=lines,
                                    max_severity=max_severity, contains=contains)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "cisco-stack-mcp", "version": __version__,
                             "stacks": inventory.names(), "read_only": True})

    return mcp, tools


def create_app(settings: Settings | None = None, **kw):
    settings = settings or Settings()
    mcp, _tools = build(settings, **kw)
    app = mcp.streamable_http_app()
    return BearerAuthMiddleware(app, TokenStore(settings.tokens_file), disabled=settings.auth_disabled)


def main() -> None:
    import uvicorn

    logging.basicConfig(level=os.environ.get("CSM_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings()
    if not settings.ssh_password:
        raise SystemExit("CSM_SSH_PASSWORD is not set (expected in /etc/cisco-stack-mcp/secrets.env)")
    if settings.auth_disabled:
        log.warning("CSM_AUTH_DISABLED=1: bearer-token auth is OFF. Never use this in production.")
    app = create_app(settings)
    uvicorn.run(app, host=settings.listen_host, port=settings.listen_port,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1", log_level="info")


if __name__ == "__main__":
    main()
