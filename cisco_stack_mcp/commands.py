"""The command allowlist.

Every command this server can send to a switch is built here, from a fixed
template plus validated arguments, and then checked again against an anchored
allowlist before it leaves the process. There is no path from a tool argument
to free-form CLI text.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Argument validators
# ---------------------------------------------------------------------------

# Canonical interface prefixes (IOS XE accepts these and their abbreviations).
_IF_PREFIXES = {
    "gigabitethernet": "GigabitEthernet",
    "gi": "GigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "te": "TenGigabitEthernet",
    "twentyfivegige": "TwentyFiveGigE",
    "twe": "TwentyFiveGigE",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "fo": "FortyGigabitEthernet",
    "hundredgige": "HundredGigE",
    "hu": "HundredGigE",
    "appgigabitethernet": "AppGigabitEthernet",
    "ap": "AppGigabitEthernet",
    "port-channel": "Port-channel",
    "po": "Port-channel",
    "vlan": "Vlan",
    "vl": "Vlan",
    "loopback": "Loopback",
    "lo": "Loopback",
}

_IF_RE = re.compile(
    r"^(?P<prefix>[A-Za-z][A-Za-z-]*?)\s*(?P<num>\d{1,4}(?:/\d{1,3}){0,2})$"
)

# Canonical form as it appears in an outgoing command.
_IF_CANON_RE = (
    r"(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|"
    r"HundredGigE|AppGigabitEthernet|Port-channel|Vlan|Loopback)"
    r"\d{1,4}(?:/\d{1,3}){0,2}"
)
_MAC_CANON_RE = r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
_VLAN_CANON_RE = r"(?:[1-9]\d{0,2}|[1-3]\d{3}|40[0-8]\d|409[0-4])"


class ArgumentError(ValueError):
    """A tool argument failed validation."""


def normalise_interface(value: str) -> str:
    """Return the canonical interface name, e.g. 'gi1/0/14' -> 'GigabitEthernet1/0/14'."""
    if not isinstance(value, str):
        raise ArgumentError("interface must be a string")
    value = value.strip()
    if len(value) > 40:
        raise ArgumentError("interface name too long")
    m = _IF_RE.match(value)
    if not m:
        raise ArgumentError(
            f"'{value}' is not a valid interface name (examples: Gi1/0/14, Te2/1/1, Po10, Vlan100)"
        )
    prefix = m.group("prefix").lower()
    canon = _IF_PREFIXES.get(prefix)
    if canon is None:
        raise ArgumentError(f"unsupported interface type '{m.group('prefix')}'")
    return f"{canon}{m.group('num')}"


def normalise_vlan(value) -> int:
    try:
        vlan = int(value)
    except (TypeError, ValueError):
        raise ArgumentError("vlan must be a number between 1 and 4094") from None
    if not 1 <= vlan <= 4094:
        raise ArgumentError("vlan must be between 1 and 4094")
    return vlan


def normalise_mac(value: str) -> str:
    """Accept aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff or aabbccddeeff."""
    if not isinstance(value, str):
        raise ArgumentError("mac must be a string")
    hexdigits = re.sub(r"[.:\-\s]", "", value.strip().lower())
    if not re.fullmatch(r"[0-9a-f]{12}", hexdigits):
        raise ArgumentError(f"'{value}' is not a valid MAC address")
    return f"{hexdigits[0:4]}.{hexdigits[4:8]}.{hexdigits[8:12]}"


# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------

_ALLOWED_PATTERNS = [
    r"show clock",
    r"show switch",
    r"show switch stack-ports summary",
    r"show redundancy",
    r"show stack-power",
    r"show version",
    r"show install summary",
    r"show inventory",
    r"show license summary",
    r"show environment all",
    r"show interfaces status",
    r"show ip interface brief",
    rf"show interfaces {_IF_CANON_RE}",
    rf"show interfaces {_IF_CANON_RE} switchport",
    r"show interfaces counters errors",
    r"show interfaces transceiver",
    r"show vlan brief",
    r"show interfaces trunk",
    r"show mac address-table",
    rf"show mac address-table address {_MAC_CANON_RE}",
    rf"show mac address-table interface {_IF_CANON_RE}",
    rf"show mac address-table vlan {_VLAN_CANON_RE}",
    r"show cdp neighbors detail",
    r"show lldp neighbors detail",
    r"show spanning-tree summary",
    r"show spanning-tree root",
    r"show etherchannel summary",
    r"show logging",
]

_ALLOWED = [re.compile(rf"^{p}$") for p in _ALLOWED_PATTERNS]

# Belt and braces: characters and words that must never appear.
_FORBIDDEN_CHARS = re.compile(r"[|;&<>`$\\\n\r\t\"'!]")
_FORBIDDEN_WORDS = re.compile(
    r"\b(redirect|tee|append|copy|configure|conf|clear|reload|debug|write|delete|"
    r"erase|format|request|install\s+(add|activate|commit|remove)|tclsh|event|"
    r"send|test|archive|more|dir|terminal|exec)\b",
    re.IGNORECASE,
)


class CommandNotAllowed(PermissionError):
    """A command failed the final allowlist check."""


def assert_allowed(command: str) -> str:
    """Final gate before a command is sent. Returns the command or raises."""
    if not isinstance(command, str) or not command.startswith("show "):
        raise CommandNotAllowed("only show commands are permitted")
    if len(command) > 120:
        raise CommandNotAllowed("command too long")
    if _FORBIDDEN_CHARS.search(command):
        raise CommandNotAllowed("command contains a forbidden character")
    # 'show install summary' is allowed; the install-verb pattern blocks the rest.
    if _FORBIDDEN_WORDS.search(command):
        raise CommandNotAllowed("command contains a forbidden keyword")
    if not any(p.match(command) for p in _ALLOWED):
        raise CommandNotAllowed(f"command not in allowlist: {command!r}")
    return command


def allowed_patterns() -> list[str]:
    return list(_ALLOWED_PATTERNS)


# ---------------------------------------------------------------------------
# Command builders used by the tools
# ---------------------------------------------------------------------------

def cmd_interface(interface: str) -> str:
    return assert_allowed(f"show interfaces {normalise_interface(interface)}")


def cmd_interface_switchport(interface: str) -> str:
    return assert_allowed(f"show interfaces {normalise_interface(interface)} switchport")


def cmd_mac_table(mac: str | None = None, vlan=None, interface: str | None = None) -> str:
    """One device-side filter (most selective first); the rest are applied in the server."""
    if mac:
        return assert_allowed(f"show mac address-table address {normalise_mac(mac)}")
    if interface:
        return assert_allowed(f"show mac address-table interface {normalise_interface(interface)}")
    if vlan is not None:
        return assert_allowed(f"show mac address-table vlan {normalise_vlan(vlan)}")
    return assert_allowed("show mac address-table")


def fixed(command: str) -> str:
    return assert_allowed(command)
