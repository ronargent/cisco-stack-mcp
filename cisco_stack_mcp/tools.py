"""Tool implementations. Independent of MCP so they can be tested directly."""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

from . import commands as C
from .audit import AuditLog
from .auth import RateLimiter, current_client
from .config import Settings
from .inventory import Inventory, InventoryError, Stack
from .parsers import cap_rows, environment_issues, mask_secrets, parse
from .ssh_pool import CommandRejected, SSHRunner, SwitchError

_STATUS_RE = re.compile(r"^[a-z][a-z-]{1,19}$")
_MEMBER_PORT_RE = re.compile(r"^[A-Za-z-]+(\d+)/")
_TEXT_FILTER_RE = re.compile(r"^[\w .:/%@()\-]{1,60}$")
_RESERVED_VLANS = {"1002", "1003", "1004", "1005"}


class ToolError(Exception):
    """An error to return to the client as a normal (non-crashing) result."""


@dataclass
class Call:
    tool: str
    commands: list[str] = field(default_factory=list)
    cached: int = 0


class StackTools:
    def __init__(self, settings: Settings, inventory: Inventory, runner: SSHRunner,
                 audit: AuditLog, limiter: RateLimiter):
        self.settings = settings
        self.inventory = inventory
        self.runner = runner
        self.audit = audit
        self.limiter = limiter

    # ------------------------------------------------------------------ plumbing

    async def _cmd(self, stack: Stack, call: Call, command: str, *, mask: bool = False,
                   use_cache: bool = True) -> dict:
        res = await self.runner.run(stack, command, use_cache=use_cache)
        call.commands.append(f"{stack.name}: {command}")
        call.cached += int(res["cached"])
        text = mask_secrets(res["output"]) if mask else res["output"]
        parsed = parse(command, text)
        rows, meta = cap_rows(parsed["rows"], self.settings.max_rows)
        out = {"command": command, "parser": parsed["parser"], "rows": rows, **meta}
        if parsed["parser"] == "raw":
            raw = parsed["raw"]
            out["raw"] = raw if len(raw) <= 20000 else raw[:20000] + "\n...[truncated]"
        return out

    async def run_tool(self, name: str, stack: str | None, impl, **args) -> dict:
        """Common wrapper: rate limit, stack resolution, fan-out for 'all', errors, audit."""
        client = current_client.get()
        started = time.monotonic()
        call = Call(tool=name)
        status, error = "ok", None
        result: dict
        try:
            if not self.limiter.check(client):
                raise ToolError(f"rate limit: more than {self.settings.rate_limit_per_min} calls a minute")
            if stack is None:
                targets = []
            else:
                targets = self.inventory.resolve(str(stack).strip())
            if not targets:
                result = await impl(None, call, **args)
            elif len(targets) == 1:
                result = {"stack": targets[0].name, **await impl(targets[0], call, **args)}
            else:
                outcomes = await asyncio.gather(*(impl(t, call, **args) for t in targets),
                                                return_exceptions=True)
                per, failures = {}, []
                for t, o in zip(targets, outcomes):
                    if isinstance(o, BaseException):
                        per[t.name] = _error_dict(o)
                        failures.append(f"{t.name}: {o}")
                    else:
                        per[t.name] = o
                if failures:
                    status = "error" if len(failures) == len(targets) else "partial"
                    error = "; ".join(failures)
                result = {"stacks": per}
        except (C.ArgumentError, InventoryError, ToolError, C.CommandNotAllowed, SwitchError) as exc:
            status, error = "error", str(exc)
            result = _error_dict(exc)
        except Exception as exc:  # noqa: BLE001 - never crash the MCP session
            status, error = "error", f"{type(exc).__name__}: {exc}"
            result = {"error": "internal error", "detail": error}
        finally:
            self.audit.write(
                client=client, tool=name, stack=stack,
                args={k: v for k, v in args.items() if v is not None},
                commands=call.commands, cached=call.cached, status=status, error=error,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        return result

    # ------------------------------------------------------------------ tools

    async def list_stacks(self, _stack, call: Call) -> dict:
        return {"stacks": [s.public() for s in self.inventory.all()],
                "read_only": True, "allowed_commands": C.allowed_patterns()}

    async def health_check(self, stack: Stack, call: Call) -> dict:
        t0 = time.monotonic()
        try:
            r = await self._cmd(stack, call, C.fixed("show clock"), use_cache=False)
        except SwitchError as exc:
            return {"reachable": False, **_error_dict(exc)}
        clock = r["rows"][0] if r["rows"] else r.get("raw", "").strip()
        return {"reachable": True, "login_ok": True, "latency_ms": int((time.monotonic() - t0) * 1000),
                "switch_clock": clock, "host": stack.host}

    async def get_stack_members(self, stack: Stack, call: Call) -> dict:
        sw, ports, red = await self._gather(stack, call, "show switch", "show switch stack-ports summary",
                                            "show redundancy")
        members = [{
            "switch": _int(r.get("switch")), "role": r.get("role"), "mac_address": r.get("mac_address"),
            "priority": _int(r.get("priority")), "hw_version": r.get("version"), "state": r.get("state"),
        } for r in sw["rows"]]
        issues = []
        ready = [m for m in members if (m["state"] or "").lower() == "ready"]
        if len(ready) < stack.expected_members:
            issues.append(f"only {len(ready)} of {stack.expected_members} expected members are Ready")
        for m in members:
            if (m["state"] or "").lower() != "ready":
                issues.append(f"switch {m['switch']} state is {m['state']}")
        if not any((m["role"] or "").lower() == "standby" for m in members) and stack.expected_members > 1:
            issues.append("no standby switch in the stack")
        for p in ports["rows"]:
            if str(p.get("status", "")).upper() != "OK":
                issues.append(f"stack port {p['switch']}/{p['port']} is {p['status']}")
        red_row = red["rows"][0] if red["rows"] else {}
        redundancy = {k: v for k, v in red_row.items()
                      if k in ("hardware_mode", "configured_redundancy_mode", "operating_redundancy_mode",
                               "communication_status", "switchovers", "standby_failures",
                               "last_switchover_reason", "active_slot", "active_software_state",
                               "standby_slot", "standby_software_state") and v}
        if stack.expected_members > 1 and red_row:
            if red_row.get("operating_redundancy_mode", "").lower() != "sso":
                issues.append(f"redundancy mode is {red_row.get('operating_redundancy_mode') or 'unknown'}, not SSO")
            if red_row.get("standby_software_state", "").upper().strip() != "STANDBY HOT":
                issues.append(f"standby state is {red_row.get('standby_software_state') or 'absent'}, not STANDBY HOT")
        return {"healthy": not issues, "issues": issues, "members": members,
                "stack_ports": ports["rows"] or ports.get("raw"), "redundancy": redundancy or red.get("raw")}

    async def get_stack_power(self, stack: Stack, call: Call) -> dict:
        r = await self._cmd(stack, call, C.fixed("show stack-power"))
        return _rows_or_raw(r, "power_stacks")

    async def get_version(self, stack: Stack, call: Call) -> dict:
        ver, inst = await self._gather(stack, call, "show version", "show install summary")
        v = ver["rows"][0] if ver["rows"] else {}
        keep = ("hostname", "version", "release", "software_image", "running_image", "uptime",
                "reload_reason", "restarted", "hardware", "serial", "mac_address", "config_register")
        summary = {k: v[k] for k in keep if v.get(k) not in (None, "", [])}
        out = {"version": summary or ver.get("raw"), "install": inst["rows"] or inst.get("raw")}
        if inst["rows"]:
            states = {i["state"] for i in inst["rows"]}
            out["install_committed"] = states == {"Activated & Committed"}
        return out

    async def get_inventory(self, stack: Stack, call: Call) -> dict:
        inv, lic = await self._gather(stack, call, "show inventory", "show license summary")
        items = [{"name": r.get("name"), "description": r.get("descr"), "pid": (r.get("pid") or "").strip(),
                  "vid": (r.get("vid") or "").strip(), "serial": (r.get("sn") or "").strip()} for r in inv["rows"]]
        return {"items": items or inv.get("raw"), "licenses": lic["rows"] or lic.get("raw")}

    async def get_environment(self, stack: Stack, call: Call) -> dict:
        r = await self._cmd(stack, call, C.fixed("show environment all"))
        if not r["rows"]:
            return {"raw": r.get("raw")}
        issues = environment_issues(r["rows"])
        return {"healthy": not issues, "issues": issues, "sensors": r["rows"]}

    async def get_interfaces(self, stack: Stack, call: Call, member: int | None = None,
                             status: str | None = None, vlan: str | None = None,
                             include_l3: bool = False) -> dict:
        if member is not None and not 1 <= int(member) <= 8:
            raise C.ArgumentError("member must be 1-8")
        if status is not None and not _STATUS_RE.match(status):
            raise C.ArgumentError("status must be a word such as connected, notconnect, err-disabled, disabled")
        if vlan is not None and str(vlan) != "trunk":
            vlan = str(C.normalise_vlan(vlan))
        r = await self._cmd(stack, call, C.fixed("show interfaces status"))
        rows = r["rows"]
        if member is not None:
            rows = [x for x in rows if (m := _MEMBER_PORT_RE.match(x.get("port", ""))) and int(m.group(1)) == int(member)]
        if status:
            rows = [x for x in rows if x.get("status") == status]
        if vlan is not None:
            rows = [x for x in rows if str(x.get("vlan_id")) == str(vlan)]
        counts: dict[str, int] = {}
        for x in r["rows"]:
            counts[x.get("status", "?")] = counts.get(x.get("status", "?"), 0) + 1
        out = {"status_counts": counts, "interfaces": rows if r["rows"] else r.get("raw")}
        if include_l3:
            l3 = await self._cmd(stack, call, C.fixed("show ip interface brief"))
            out["l3_interfaces"] = l3["rows"] or l3.get("raw")
        return out

    async def get_interface_detail(self, stack: Stack, call: Call, interface: str) -> dict:
        name = C.normalise_interface(interface)
        r = await self._cmd(stack, call, C.cmd_interface(name))
        out = {"interface": name, "detail": r["rows"][0] if r["rows"] else r.get("raw")}
        if not name.startswith(("Vlan", "Loopback")):
            try:
                sp = await self._cmd(stack, call, C.cmd_interface_switchport(name))
                out["switchport"] = sp["rows"][0] if sp["rows"] else sp.get("raw")
            except CommandRejected:
                out["switchport"] = None
        return out

    async def get_interface_errors(self, stack: Stack, call: Call, nonzero_only: bool = True) -> dict:
        r = await self._cmd(stack, call, C.fixed("show interfaces counters errors"))
        rows = r["rows"]
        if nonzero_only:
            rows = [{"port": x["port"], **{k: v for k, v in x.items() if k != "port" and v}}
                    for x in rows if any(isinstance(v, int) and v for k, v in x.items() if k != "port")]
        return {"ports": rows if r["rows"] else r.get("raw"), "ports_with_errors": len(
            [x for x in r["rows"] if any(isinstance(v, int) and v for k, v in x.items() if k != "port")])}

    async def get_transceivers(self, stack: Stack, call: Call) -> dict:
        r = await self._cmd(stack, call, C.fixed("show interfaces transceiver"))
        if not r["rows"]:
            return {"transceivers": [], "raw": r.get("raw")}
        alarms = [{"port": x["port"], **x["alarms"]} for x in r["rows"] if x.get("alarms")]
        return {"transceivers": r["rows"], "alarms": alarms}

    async def get_vlans(self, stack: Stack, call: Call, include_reserved: bool = False) -> dict:
        vl, tr = await self._gather(stack, call, "show vlan brief", "show interfaces trunk")
        rows = vl["rows"]
        if not include_reserved:
            rows = [x for x in rows if str(x.get("vlan_id")) not in _RESERVED_VLANS]
        return {"vlans": rows if vl["rows"] else vl.get("raw"), "trunks": tr["rows"] or tr.get("raw") or []}

    async def find_mac(self, stack: Stack, call: Call, mac: str | None = None, vlan=None,
                       interface: str | None = None, include_static: bool = False) -> dict:
        mac_n = C.normalise_mac(mac) if mac else None
        vlan_n = C.normalise_vlan(vlan) if vlan is not None else None
        if_n = C.normalise_interface(interface) if interface else None
        r = await self._cmd(stack, call, C.cmd_mac_table(mac_n, vlan_n, if_n))
        entries = [{"vlan": x.get("vlan_id"), "mac": x.get("destination_address"), "type": x.get("type"),
                    "ports": x.get("destination_port")} for x in r["rows"]]
        if not include_static:
            entries = [e for e in entries if (e["type"] or "").upper() != "STATIC"]
        if mac_n:
            entries = [e for e in entries if e["mac"] == mac_n]
        if vlan_n is not None:
            entries = [e for e in entries if str(e["vlan"]) == str(vlan_n)]
        if if_n:
            short = _short_if(if_n)
            entries = [e for e in entries if short in (e["ports"] or []) or if_n in (e["ports"] or [])]
        return {"entries": entries, "count": len(entries)}

    async def get_neighbors(self, stack: Stack, call: Call, protocol: str = "both") -> dict:
        if protocol not in ("cdp", "lldp", "both"):
            raise C.ArgumentError("protocol must be cdp, lldp or both")
        out = {}
        for proto in ("cdp", "lldp"):
            if protocol not in (proto, "both"):
                continue
            try:
                r = await self._cmd(stack, call, C.fixed(f"show {proto} neighbors detail"))
            except CommandRejected as exc:
                out[proto] = {"error": str(exc)}
                continue
            raw = r.get("raw") or ""
            if not r["rows"] and "not enabled" in raw.lower():
                out[proto] = {"enabled": False}
            else:
                out[proto] = r["rows"] if r["rows"] else {"raw": raw}
        return out

    async def get_spanning_tree(self, stack: Stack, call: Call) -> dict:
        summ, root = await self._gather(stack, call, "show spanning-tree summary", "show spanning-tree root")
        s = summ["rows"][0] if summ["rows"] else {"raw": summ.get("raw")}
        return {"summary": s, "roots": root["rows"] or root.get("raw")}

    async def get_etherchannels(self, stack: Stack, call: Call) -> dict:
        r = await self._cmd(stack, call, C.fixed("show etherchannel summary"))
        rows = r["rows"]
        problems = []
        for x in rows:
            if "U" not in (x.get("bundle_status") or ""):
                problems.append(f"{x.get('bundle_name')} not in use ({x.get('bundle_status')})")
            for mi, ms in zip(x.get("member_interface") or [], x.get("member_interface_status") or []):
                if "P" not in ms:
                    problems.append(f"{x.get('bundle_name')} member {mi} not bundled ({ms})")
        return {"etherchannels": rows if rows else r.get("raw"), "problems": problems}

    async def get_logs(self, stack: Stack, call: Call, lines: int = 100, max_severity: int = 7,
                       contains: str | None = None) -> dict:
        lines = int(lines)
        if not 1 <= lines <= 500:
            raise C.ArgumentError("lines must be 1-500")
        max_severity = int(max_severity)
        if not 0 <= max_severity <= 7:
            raise C.ArgumentError("max_severity must be 0 (emergencies) to 7 (debugging)")
        if contains is not None and not _TEXT_FILTER_RE.match(contains):
            raise C.ArgumentError("contains must be 1-60 plain characters")
        r = await self._cmd(stack, call, C.fixed("show logging"), mask=True)
        msgs = []
        for x in r["rows"]:
            sev = _int(x.get("severity"))
            if sev is not None and sev > max_severity:
                continue
            text = " ".join(x.get("message") or []) if isinstance(x.get("message"), list) else x.get("message", "")
            if contains and contains.lower() not in f"{x.get('facility')} {x.get('mnemonic')} {text}".lower():
                continue
            msgs.append({"time": " ".join(filter(None, [x.get("month"), x.get("day"), x.get("time"), x.get("timezone")])),
                         "facility": x.get("facility"), "severity": sev, "mnemonic": x.get("mnemonic"),
                         "message": text})
        return {"messages": msgs[-lines:], "matched": len(msgs)} if r["rows"] else {"raw": r.get("raw")}

    async def stack_summary(self, stack: Stack, call: Call) -> dict:
        members = await self.get_stack_members(stack, call)
        ifs = await self.get_interfaces(stack, call)
        errs = await self.get_interface_errors(stack, call)
        env = await self.get_environment(stack, call)
        logs = await self.get_logs(stack, call, lines=10, max_severity=3)
        issues = list(members["issues"])
        if env.get("issues"):
            issues += [f"environment: {i.get('name')} on switch {i.get('switch')} is {i.get('state')}"
                       for i in env["issues"]]
        errd = ifs["status_counts"].get("err-disabled", 0)
        if errd:
            issues.append(f"{errd} interface(s) err-disabled")
        if errs.get("ports_with_errors"):
            issues.append(f"{errs['ports_with_errors']} port(s) with non-zero error counters")
        return {
            "healthy": not issues,
            "issues": issues,
            "members": [{k: m[k] for k in ("switch", "role", "state")} for m in members["members"]],
            "interface_status_counts": ifs["status_counts"],
            "ports_with_errors": errs.get("ports", []),
            "environment_healthy": env.get("healthy"),
            "recent_errors_in_log": logs.get("messages", []),
        }

    # ------------------------------------------------------------------ helpers

    async def _gather(self, stack: Stack, call: Call, *cmds: str) -> list[dict]:
        # Same stack -> the runner serialises them on the stack lock anyway; keep it simple and ordered.
        return [await self._cmd(stack, call, C.fixed(c)) for c in cmds]


def _rows_or_raw(r: dict, key: str) -> dict:
    return {key: r["rows"]} if r["rows"] else {"raw": r.get("raw")}


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _short_if(name: str) -> str:
    for long, short in (("GigabitEthernet", "Gi"), ("TenGigabitEthernet", "Te"), ("TwentyFiveGigE", "Twe"),
                        ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"), ("Port-channel", "Po"),
                        ("AppGigabitEthernet", "Ap")):
        if name.startswith(long):
            return short + name[len(long):]
    return name


def _error_dict(exc: BaseException) -> dict:
    return {"error": str(exc), "error_type": type(exc).__name__}
