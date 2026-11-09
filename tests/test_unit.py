import asyncio
import json
import os

import pytest

from cisco_stack_mcp import commands as C
from cisco_stack_mcp.auth import RateLimiter, TokenStore
from cisco_stack_mcp.inventory import Inventory, InventoryError
from cisco_stack_mcp.parsers import environment_issues, mask_secrets, parse
from cisco_stack_mcp.ssh_pool import CommandRejected, _check_rejection

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "core-a")


def fx(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------- allowlist

@pytest.mark.parametrize("cmd", [
    "show switch", "show version", "show interfaces GigabitEthernet1/0/14",
    "show interfaces TenGigabitEthernet2/1/1 switchport", "show mac address-table address 0090.fa11.2233",
    "show mac address-table vlan 4094", "show mac address-table interface Port-channel10", "show logging",
    "show install summary",
])
def test_allowed(cmd):
    assert C.assert_allowed(cmd) == cmd


@pytest.mark.parametrize("cmd", [
    "configure terminal", "reload", "clear counters", "copy run start", "debug all",
    "show running-config", "show tech-support", "show logging | redirect flash:x",
    "show switch; reload", "show switch\nreload", "show version | tee flash:x",
    "show interfaces Gi1/0/1", "show mac address-table vlan 4095", "show mac address-table vlan 0",
    "show install add file flash:x", "show interfaces GigabitEthernet1/0/1 ; reload",
    "show clock\r", "show  switch", "SHOW SWITCH", "write memory", "show archive",
])
def test_rejected(cmd):
    with pytest.raises(C.CommandNotAllowed):
        C.assert_allowed(cmd)


@pytest.mark.parametrize("raw,expected", [
    ("gi1/0/14", "GigabitEthernet1/0/14"), ("Gi2/0/1", "GigabitEthernet2/0/1"),
    ("te1/1/1", "TenGigabitEthernet1/1/1"), ("Po10", "Port-channel10"), ("vlan20", "Vlan20"),
    ("TenGigabitEthernet2/1/4", "TenGigabitEthernet2/1/4"), ("twe1/1/1", "TwentyFiveGigE1/1/1"),
])
def test_interface_normalise(raw, expected):
    assert C.normalise_interface(raw) == expected


@pytest.mark.parametrize("bad", [
    "Gi1/0/1; reload", "Gi1/0/1 | redirect", "Gi1/0/1\nreload", "eth0", "Gi1/0/1/2/3", "", "x" * 50,
    "Serial0/0", "Gi/0/1", "Gi1/0/1 switchport",
])
def test_interface_bad(bad):
    with pytest.raises(C.ArgumentError):
        C.normalise_interface(bad)


@pytest.mark.parametrize("raw", ["00:90:FA:11:22:33", "0090.fa11.2233", "00-90-fa-11-22-33", "0090fa112233"])
def test_mac_normalise(raw):
    assert C.normalise_mac(raw) == "0090.fa11.2233"


@pytest.mark.parametrize("bad", ["0090.fa11.223", "zz:90:fa:11:22:33", "0090.fa11.2233; reload", 12])
def test_mac_bad(bad):
    with pytest.raises(C.ArgumentError):
        C.normalise_mac(bad)


@pytest.mark.parametrize("bad", [0, 4095, "abc", "10;reload", None])
def test_vlan_bad(bad):
    with pytest.raises(C.ArgumentError):
        C.normalise_vlan(bad)


def test_mac_table_builder_prefers_most_selective():
    assert C.cmd_mac_table("00:90:fa:11:22:33", 20, "gi1/0/3") == "show mac address-table address 0090.fa11.2233"
    assert C.cmd_mac_table(None, 20, "gi1/0/3") == "show mac address-table interface GigabitEthernet1/0/3"
    assert C.cmd_mac_table(None, "20") == "show mac address-table vlan 20"
    assert C.cmd_mac_table() == "show mac address-table"


# ---------------------------------------------------------------- parsers

def test_every_fixture_parses_to_rows():
    for d in ("core-a", "core-b"):
        base = os.path.join(os.path.dirname(__file__), "fixtures", d)
        for f in os.listdir(base):
            cmd = f[:-4].replace("_", " ").replace("GigabitEthernet1 0 1", "GigabitEthernet1/0/1")
            r = parse(cmd, open(os.path.join(base, f)).read())
            assert r["parser"] != "raw", f"{d}/{f} did not parse"
            assert r["rows"], f"{d}/{f} parsed to nothing"


def test_stack_ports():
    rows = parse("show switch stack-ports summary", fx("show_switch_stack-ports_summary.txt"))["rows"]
    assert len(rows) == 4 and all(r["status"] == "OK" and r["link_ok"] is True for r in rows)


def test_environment_and_issues():
    rows = parse("show environment all", fx("show_environment_all.txt"))["rows"]
    kinds = {r["kind"] for r in rows}
    assert {"fan", "temperature", "power_supply", "rps", "system_temperature"} <= kinds
    inlet = [r for r in rows if r["kind"] == "temperature" and r["name"] == "Inlet"]
    assert inlet[0]["celsius"] == 27 and inlet[0]["state"] == "GREEN" and inlet[0]["red_threshold"] == 56
    assert environment_issues(rows) == []
    bad = rows + [{"kind": "fan", "switch": 2, "name": "FAN 3", "state": "FAULTY"},
                  {"kind": "power_supply", "switch": 1, "name": "PS 1A", "state": "Bad"}]
    assert len(environment_issues(bad)) == 2


def test_counters_errors_merges_tables():
    rows = parse("show interfaces counters errors", fx("show_interfaces_counters_errors.txt"))["rows"]
    g5 = next(r for r in rows if r["port"] == "Gi1/0/5")
    assert g5["fcs_err"] == 231 and g5["runts"] == 9 and len(rows) == 9


def test_transceiver_alarm_flag():
    rows = parse("show interfaces transceiver", fx("show_interfaces_transceiver.txt"))["rows"]
    te2 = next(r for r in rows if r["port"] == "Te2/1/1")
    assert te2["rx_power_dbm"] == -14.9 and te2["alarms"] == {"rx_power": "low_warning"}


def test_trunks():
    rows = parse("show interfaces trunk", fx("show_interfaces_trunk.txt"))["rows"]
    po = next(r for r in rows if r["port"] == "Po10")
    assert po["native_vlan"] == "99" and po["allowed_vlans"] == "1-4094" and po["forwarding_vlans"] == "1,10,20,30,99"


def test_garbled_output_falls_back_to_raw():
    r = parse("show environment all", "something unexpected\nfrom a future release\n")
    assert r["parser"] == "raw" and "future release" in r["raw"]


def test_mask_secrets():
    s = mask_secrets("username admin secret 9 $9$abc\n snmp-server community public RO\n key 7 0822455D0A16")
    assert "$9$abc" not in s and "public" not in s and "0822455D0A16" not in s


def test_rejection_detected():
    with pytest.raises(CommandRejected):
        _check_rejection("show x", "                ^\n% Invalid input detected at '^' marker.\n")
    with pytest.raises(CommandRejected):
        _check_rejection("show x", "Command authorization failed.\n")
    _check_rejection("show logging", fx("show_logging.txt"))  # % in log lines is not a rejection


# ---------------------------------------------------------------- inventory / auth

def test_inventory_validation():
    inv = Inventory.from_dict({"stacks": [{"name": "core-a", "host": "10.0.0.1"},
                                          {"name": "core-b", "host": "sw-b.tes.local", "expected_members": 2}]})
    assert [s.name for s in inv.resolve("all")] == ["core-a", "core-b"]
    with pytest.raises(InventoryError):
        inv.get("core-c")
    for bad in ({"stacks": []}, {"stacks": [{"name": "Bad Name", "host": "1.1.1.1"}]},
                {"stacks": [{"name": "a", "host": "1.1.1.1; reboot"}]},
                {"stacks": [{"name": "a", "host": "1.1.1.1", "expected_members": 9}]},
                {"stacks": [{"name": "a", "host": "1.1.1.1"}, {"name": "a", "host": "1.1.1.2"}]}):
        with pytest.raises(InventoryError):
            Inventory.from_dict(bad)


def test_token_store(tmp_path):
    store = TokenStore(str(tmp_path / "tokens.json"))
    t1 = store.add("aios")
    t2 = store.add("claude-code")
    assert store.identify(t1) == "aios" and store.identify(t2) == "claude-code"
    assert store.identify("wrong") is None
    raw = json.loads((tmp_path / "tokens.json").read_text())
    assert t1 not in json.dumps(raw)  # only hashes on disk
    t1b = store.rotate("aios")
    assert store.identify(t1) is None and store.identify(t1b) == "aios"
    store.revoke("claude-code")
    assert store.identify(t2) is None
    with pytest.raises(ValueError):
        store.add("aios")


def test_rate_limiter():
    rl = RateLimiter(3)
    assert [rl.check("a") for _ in range(4)] == [True, True, True, False]
    assert rl.check("b") is True
