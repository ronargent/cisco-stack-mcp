"""Turn CLI text into rows: custom parser -> ntc-templates -> Genie (if installed) -> raw."""

from __future__ import annotations

import logging
import re
from typing import Callable

log = logging.getLogger("cisco_stack_mcp.parsers")

Rows = list[dict]


# ---------------------------------------------------------------------------
# Custom parsers for commands ntc-templates does not cover (or parses to nothing)
# ---------------------------------------------------------------------------

def _yes(v: str) -> bool | str:
    return {"yes": True, "no": False}.get(v.lower(), v)


def parse_stack_ports(text: str) -> Rows:
    rows = []
    rx = re.compile(
        r"^\s*(?P<switch>\d+)/(?P<port>\d+)\s+(?P<status>\S+)\s+(?P<neighbor>\S+)\s+"
        r"(?P<cable>\S+)\s+(?P<link_ok>\S+)\s+(?P<link_active>\S+)\s+(?P<sync_ok>\S+)\s+"
        r"(?P<changes>\d+)\s+(?P<loopback>\S+)\s*$"
    )
    for line in text.splitlines():
        m = rx.match(line)
        if m:
            d = m.groupdict()
            rows.append({
                "switch": int(d["switch"]), "port": int(d["port"]), "status": d["status"],
                "neighbor": d["neighbor"], "cable_length": d["cable"],
                "link_ok": _yes(d["link_ok"]), "link_active": _yes(d["link_active"]),
                "sync_ok": _yes(d["sync_ok"]), "changes_to_link_ok": int(d["changes"]),
                "in_loopback": _yes(d["loopback"]),
            })
    return rows


def parse_environment(text: str) -> Rows:
    """Fans, temperatures, power supplies and RPS from 'show environment all' (C9300)."""
    rows: Rows = []
    current_switch = None
    temp_sensor = None
    lines = text.splitlines()
    psu_rx = re.compile(
        r"^\s*(?P<slot>\d+[A-Z])\s+(?P<pid>\S+)\s+(?P<serial>\S+)\s+(?P<status>OK|Bad|No Input Power|\S+)"
        r"\s+(?P<sys_pwr>\S+)\s+(?P<poe_pwr>\S+)\s+(?P<watts>\d+)\s*$"
    )
    psu_absent_rx = re.compile(r"^\s*(?P<slot>\d+[A-Z])\s+Not Present\s*$", re.I)
    fan_rx = re.compile(r"^\s*(?:Switch:?\s*(?P<sw>\d+)\s+)?FAN\s+(?P<fan>[\w-]+)\s+is\s+(?P<state>.+?)\s*$", re.I)
    systemp_rx = re.compile(r"^\s*Switch\s+(?P<sw>\d+):\s+SYSTEM TEMPERATURE is\s+(?P<state>.+?)\s*$", re.I)
    tval_rx = re.compile(r"^\s*(?P<sensor>[\w ]+?) Temperature Value:\s*(?P<val>-?\d+)", re.I)
    tstate_rx = re.compile(r"^\s*Temperature State:\s*(?P<state>\S+)", re.I)
    yel_rx = re.compile(r"^\s*Yellow Threshold\s*:\s*(?P<v>-?\d+)", re.I)
    red_rx = re.compile(r"^\s*Red Threshold\s*:\s*(?P<v>-?\d+)", re.I)
    rps_rx = re.compile(r"^\s*(?P<sw>\d+)\s+(?P<status>Not Present|\S+(?: \S+)?)\s+<", re.I)
    in_rps = False
    for line in lines:
        if re.match(r"^\s*SW\s+Status\s+RPS", line):
            in_rps = True
            continue
        m = fan_rx.match(line)
        if m:
            if m.group("sw"):
                current_switch = int(m.group("sw"))
            rows.append({"kind": "fan", "switch": current_switch, "name": f"FAN {m.group('fan')}",
                         "state": m.group("state").strip()})
            continue
        m = systemp_rx.match(line)
        if m:
            current_switch = int(m.group("sw"))
            rows.append({"kind": "system_temperature", "switch": current_switch, "name": "system",
                         "state": m.group("state").strip()})
            continue
        m = tval_rx.match(line)
        if m:
            temp_sensor = {"kind": "temperature", "switch": current_switch,
                           "name": m.group("sensor").strip(), "celsius": int(m.group("val"))}
            rows.append(temp_sensor)
            continue
        if temp_sensor is not None:
            if (m := tstate_rx.match(line)):
                temp_sensor["state"] = m.group("state")
                continue
            if (m := yel_rx.match(line)):
                temp_sensor["yellow_threshold"] = int(m.group("v"))
                continue
            if (m := red_rx.match(line)):
                temp_sensor["red_threshold"] = int(m.group("v"))
                continue
        if (m := psu_rx.match(line)) and not in_rps:
            d = m.groupdict()
            rows.append({"kind": "power_supply", "switch": int(re.match(r"\d+", d["slot"]).group()),
                         "name": f"PS {d['slot']}", "pid": d["pid"], "serial": d["serial"],
                         "state": d["status"], "sys_pwr": d["sys_pwr"], "poe_pwr": d["poe_pwr"],
                         "watts": int(d["watts"])})
            continue
        if (m := psu_absent_rx.match(line)) and not in_rps:
            slot = m.group("slot")
            rows.append({"kind": "power_supply", "switch": int(re.match(r"\d+", slot).group()),
                         "name": f"PS {slot}", "state": "Not Present"})
            continue
        if in_rps and (m := rps_rx.match(line)):
            rows.append({"kind": "rps", "switch": int(m.group("sw")), "name": "RPS",
                         "state": m.group("status").strip()})
    return rows


_HEALTHY = {"ok", "green", "good", "not present", "normal"}


def environment_issues(rows: Rows) -> Rows:
    """Anything not in a healthy state. An absent second PSU or RPS is reported as info, not an issue."""
    issues = []
    for r in rows:
        state = str(r.get("state", "")).lower()
        if r.get("kind") == "power_supply" and state == "not present":
            continue
        if r.get("kind") in ("fan",) and state == "not present":
            continue
        if state and state not in _HEALTHY:
            issues.append(r)
    return issues


def parse_counters_errors(text: str) -> Rows:
    """Merge the two tables of 'show interfaces counters errors' into one row per port."""
    by_port: dict[str, dict] = {}
    headers: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if parts[0] == "Port":
            headers = [_snake(h) for h in parts[1:]]
            continue
        if headers and len(parts) == len(headers) + 1 and all(p.isdigit() for p in parts[1:]):
            row = by_port.setdefault(parts[0], {"port": parts[0]})
            for h, v in zip(headers, parts[1:]):
                row[h] = int(v)
    return list(by_port.values())


def _snake(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", h.lower()).strip("_")


def parse_transceiver(text: str) -> Rows:
    rows = []
    rx = re.compile(
        r"^\s*(?P<port>[A-Za-z]+\d+(?:/\d+)+)\s+(?P<temp>-?[\d.]+)\s*(?P<ta>[+-]{0,2})\s+"
        r"(?P<volt>-?[\d.]+)\s*(?P<va>[+-]{0,2})\s+(?P<curr>-?[\d.]+)\s*(?P<ca>[+-]{0,2})\s+"
        r"(?P<tx>-?[\d.]+|N/?A)\s*(?P<txa>[+-]{0,2})\s+(?P<rx>-?[\d.]+|N/?A)\s*(?P<rxa>[+-]{0,2})\s*$"
    )
    flag = {"++": "high_alarm", "+": "high_warning", "-": "low_warning", "--": "low_alarm", "": None}

    def num(v):
        try:
            return float(v)
        except ValueError:
            return None

    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        d = m.groupdict()
        alarms = {k: flag[d[a]] for k, a in
                  (("temperature", "ta"), ("voltage", "va"), ("current", "ca"), ("tx_power", "txa"), ("rx_power", "rxa"))
                  if flag[d[a]]}
        rows.append({"port": d["port"], "temperature_c": num(d["temp"]), "voltage_v": num(d["volt"]),
                     "current_ma": num(d["curr"]), "tx_power_dbm": num(d["tx"]), "rx_power_dbm": num(d["rx"]),
                     "alarms": alarms})
    return rows


def parse_trunks(text: str) -> Rows:
    sections = {
        "Mode": None,
        "Vlans allowed on trunk": "allowed_vlans",
        "Vlans allowed and active in management domain": "active_vlans",
        "Vlans in spanning tree forwarding state and not pruned": "forwarding_vlans",
    }
    by_port: dict[str, dict] = {}
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("Port"):
            title = line[4:].strip()
            current = "mode" if title.startswith("Mode") else sections.get(title, _snake(title))
            continue
        parts = line.split()
        if current == "mode" and len(parts) >= 5:
            by_port.setdefault(parts[0], {"port": parts[0]}).update(
                mode=parts[1], encapsulation=parts[2], status=parts[3], native_vlan=parts[4])
        elif current and len(parts) >= 1:
            by_port.setdefault(parts[0], {"port": parts[0]})[current] = parts[1] if len(parts) > 1 else "none"
    return list(by_port.values())


def parse_install_summary(text: str) -> Rows:
    rows = []
    switches = None
    m = re.search(r"\[\s*Switch\s+([\d ]+)\]", text)
    if m:
        switches = [int(x) for x in m.group(1).split()]
    state_names = {"I": "Inactive", "U": "Activated & Uncommitted", "C": "Activated & Committed",
                   "D": "Deactivated & Uncommitted"}
    for line in text.splitlines():
        mm = re.match(r"^\s*(IMG|SMU|APSP|APDP|ROMMON)\s+([IUCD])\s+(\S+)", line)
        if mm:
            rows.append({"type": mm.group(1), "state": state_names.get(mm.group(2), mm.group(2)),
                         "version": mm.group(3), "switches": switches})
    timer = re.search(r"Auto abort timer:\s*(.+)", text)
    if timer:
        for r in rows:
            r["auto_abort_timer"] = timer.group(1).strip()
    return rows


def parse_license_summary(text: str) -> Rows:
    rows = []
    rx = re.compile(r"^\s*(?P<license>[\w.-]+)\s+\((?P<tag>[^)]*)\)\s+(?P<count>\d+)\s+(?P<status>.+?)\s*$")
    for line in text.splitlines():
        m = rx.match(line)
        if m:
            d = m.groupdict()
            rows.append({"license": d["license"], "entitlement_tag": d["tag"],
                         "count": int(d["count"]), "status": d["status"]})
    return rows


def parse_stp_summary(text: str) -> Rows:
    row: dict = {}
    if (m := re.search(r"Switch is in (\S+) mode", text)):
        row["mode"] = m.group(1)
    if (m := re.search(r"Root bridge for:\s*(.+)", text)):
        row["root_bridge_for"] = [v.strip() for v in m.group(1).split(",") if v.strip()]
    else:
        row["root_bridge_for"] = []
    vlans = []
    for line in text.splitlines():
        m = re.match(r"^\s*(VLAN\d+|MST\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if m:
            vlans.append({"vlan": m.group(1), "blocking": int(m.group(2)), "listening": int(m.group(3)),
                          "learning": int(m.group(4)), "forwarding": int(m.group(5)),
                          "stp_active": int(m.group(6))})
    row["vlans"] = vlans
    row["blocking_total"] = sum(v["blocking"] for v in vlans)
    return [row] if (vlans or "mode" in row) else []


CUSTOM: dict[str, Callable[[str], Rows]] = {
    "show switch stack-ports summary": parse_stack_ports,
    "show environment all": parse_environment,
    "show interfaces counters errors": parse_counters_errors,
    "show interfaces transceiver": parse_transceiver,
    "show interfaces trunk": parse_trunks,
    "show install summary": parse_install_summary,
    "show license summary": parse_license_summary,
    "show spanning-tree summary": parse_stp_summary,
}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _ntc(command: str, text: str) -> Rows | None:
    try:
        from ntc_templates.parse import parse_output
        rows = parse_output(platform="cisco_ios", command=command, data=text)
        return rows or None
    except Exception as exc:  # noqa: BLE001 - template missing or mismatched
        log.debug("ntc-templates could not parse %r: %s", command, exc)
        return None


def _genie(command: str, text: str) -> Rows | None:
    try:
        from genie.conf.base import Device  # type: ignore
    except ImportError:
        return None
    try:
        dev = Device("x", os="iosxe")
        dev.custom.setdefault("abstraction", {})["order"] = ["os"]
        parsed = dev.parse(command, output=text)
        return [parsed] if parsed else None
    except Exception as exc:  # noqa: BLE001
        log.debug("genie could not parse %r: %s", command, exc)
        return None


def parse(command: str, text: str) -> dict:
    """Return {'parser': name, 'rows': [...]} or {'parser': 'raw', 'rows': [], 'raw': text}."""
    custom = CUSTOM.get(command)
    if custom is not None:
        try:
            rows = custom(text)
            if rows:
                return {"parser": "custom", "rows": rows}
        except Exception as exc:  # noqa: BLE001
            log.warning("custom parser for %r failed: %s", command, exc)
    rows = _ntc(command, text)
    if rows:
        return {"parser": "ntc-templates", "rows": rows}
    rows = _genie(command, text)
    if rows:
        return {"parser": "genie", "rows": rows}
    return {"parser": "raw", "rows": [], "raw": text}


def cap_rows(rows: Rows, limit: int) -> tuple[Rows, dict]:
    if len(rows) > limit:
        return rows[:limit], {"truncated": True, "total_rows": len(rows), "returned_rows": limit}
    return rows, {}


_SECRET_RX = re.compile(
    r"(?i)\b(secret|password|key-string|key|community|server-key|pre-shared-key)(\s+\d)?\s+\S+"
)


def mask_secrets(text: str) -> str:
    return _SECRET_RX.sub(lambda m: f"{m.group(1)}{m.group(2) or ''} <masked>", text)
