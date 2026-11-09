"""End to end: mock switches over SSH <- real server (subprocess) <- HTTP JSON-RPC, as AIOS calls it."""

import json
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"port {port} never opened")


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    pa, pb, http = _free_port(), _free_port(), _free_port()
    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_switch.py"), f"core-a:{pa}", f"core-b:{pb}"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    _wait_port(pa)
    _wait_port(pb)
    (tmp / "stacks.yaml").write_text(
        f"stacks:\n  - name: core-a\n    host: 127.0.0.1\n    port: {pa}\n    site: test\n    expected_members: 2\n"
        f"  - name: core-b\n    host: 127.0.0.1\n    port: {pb}\n    site: test\n    expected_members: 2\n")
    sys.path.insert(0, ROOT)
    from cisco_stack_mcp.auth import TokenStore
    store = TokenStore(str(tmp / "tokens.json"))
    token = store.add("aios")
    other = store.add("claude-code")
    envv = dict(os.environ, CSM_INVENTORY=str(tmp / "stacks.yaml"), CSM_TOKENS_FILE=str(tmp / "tokens.json"),
                CSM_AUDIT_LOG=str(tmp / "audit.jsonl"), CSM_SSH_PASSWORD="test-password",
                CSM_PORT=str(http), CSM_RATE_LIMIT="200", PYTHONPATH=ROOT)
    srv = subprocess.Popen([sys.executable, "-m", "cisco_stack_mcp.server"], env=envv, cwd=ROOT,
                           stdout=open(tmp / "server.log", "w"), stderr=subprocess.STDOUT)
    _wait_port(http)
    yield {"url": f"http://127.0.0.1:{http}", "token": token, "other": other, "tmp": tmp}
    srv.terminate()
    mock.terminate()
    srv.wait(5)
    mock.wait(5)


def rpc(env, method, params=None, token=None, rid=1):
    r = httpx.post(env["url"] + "/mcp", timeout=90,
                   headers={"Authorization": f"Bearer {token or env['token']}",
                            "Accept": "application/json, text/event-stream",
                            "Content-Type": "application/json"},
                   json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
    return r


def call(env, name, **args):
    r = rpc(env, "tools/call", {"name": name, "arguments": args})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "error" not in body, body
    res = body["result"]
    data = res.get("structuredContent")
    if data is None:
        data = json.loads(res["content"][0]["text"])
    return data.get("result", data) if isinstance(data, dict) and set(data) == {"result"} else data


def test_health_public(env):
    r = httpx.get(env["url"] + "/health")
    assert r.status_code == 200 and r.json()["read_only"] is True


def test_auth_required(env):
    assert rpc(env, "tools/list", token="nope").status_code == 401
    r = httpx.post(env["url"] + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401


def test_initialize_and_list(env):
    r = rpc(env, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1"}})
    assert r.status_code == 200 and r.json()["result"]["serverInfo"]["name"] == "cisco-stack-mcp"
    tools = rpc(env, "tools/list").json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert len(names) == 18
    assert all(t["annotations"]["readOnlyHint"] is True for t in tools)
    assert not any(w in n for n in names for w in ("set", "clear", "config", "reload", "write", "exec"))


def test_list_stacks(env):
    d = call(env, "list_stacks")
    assert [s["name"] for s in d["stacks"]] == ["core-a", "core-b"]


def test_health_check_all(env):
    d = call(env, "health_check", stack="all")
    assert d["stacks"]["core-a"]["reachable"] and d["stacks"]["core-b"]["reachable"]


def test_stack_members_flags_degraded_stack(env):
    d = call(env, "get_stack_members", stack="all")
    a, b = d["stacks"]["core-a"], d["stacks"]["core-b"]
    assert a["healthy"] is True and len(a["members"]) == 2
    assert a["redundancy"]["standby_software_state"].strip() == "STANDBY HOT"
    assert b["healthy"] is False
    assert any("1 of 2" in i for i in b["issues"]) and any("stack port 1/1 is DOWN" in i for i in b["issues"])


def test_stack_summary(env):
    d = call(env, "stack_summary", stack="core-a")
    assert d["stack"] == "core-a"
    assert any("err-disabled" in i for i in d["issues"])
    assert any(p["port"] == "Gi1/0/5" for p in d["ports_with_errors"])
    assert d["interface_status_counts"]["connected"] == 9
    assert all(m["severity"] <= 3 for m in d["recent_errors_in_log"])


def test_find_mac_any_format_across_stacks(env):
    d = call(env, "find_mac", stack="core-a", mac="00:90:FA:11:22:33")
    assert d["count"] == 1 and d["entries"][0]["ports"] == ["Gi1/0/3"] and d["entries"][0]["vlan"] == "20"


def test_interface_detail(env):
    d = call(env, "get_interface_detail", stack="core-a", interface="gi1/0/1")
    assert d["interface"] == "GigabitEthernet1/0/1"
    assert d["detail"]["description"] == "SRV-ESX01 vmnic0"
    assert d["switchport"]["mode"] == "trunk"


def test_filters(env):
    d = call(env, "get_interfaces", stack="core-a", member=2, status="connected")
    assert d["interfaces"] and all(i["port"].startswith(("Gi2/", "Te2/")) for i in d["interfaces"])
    d = call(env, "get_logs", stack="core-a", max_severity=4)
    assert {m["mnemonic"] for m in d["messages"]} >= {"ERR_DISABLE", "UPDOWN"}
    assert all(m["severity"] <= 4 for m in d["messages"])


def test_other_tools_run(env):
    for name in ("get_stack_power", "get_version", "get_inventory", "get_environment", "get_interface_errors",
                 "get_transceivers", "get_vlans", "get_neighbors", "get_spanning_tree", "get_etherchannels"):
        d = call(env, name, stack="core-a")
        assert "error" not in d, (name, d)
    v = call(env, "get_version", stack="core-a")
    assert v["version"]["version"] == "17.15.5" and v["install_committed"] is True
    t = call(env, "get_transceivers", stack="core-a")
    assert t["alarms"] == [{"port": "Te2/1/1", "rx_power": "low_warning"}]


def test_injection_attempts_never_reach_switch(env):
    for args in ({"interface": "Gi1/0/1 ; reload"}, {"interface": "Gi1/0/1\nconfigure terminal"},
                 {"interface": "Gi1/0/1 | redirect flash:x"}):
        d = call(env, "get_interface_detail", stack="core-a", **args)
        assert d["error_type"] == "ArgumentError"
    d = call(env, "find_mac", stack="core-a", vlan=5000)
    assert d["error_type"] == "ArgumentError"
    d = call(env, "get_logs", stack="core-a", contains="x; reload\n")
    assert d["error_type"] == "ArgumentError"
    d = call(env, "health_check", stack="../../etc")
    assert d["error_type"] == "InventoryError"


def test_all_stacks_failure_is_logged_as_error(env):
    d = call(env, "get_interface_detail", stack="all", interface="Gi1/0/1 ; reload")
    assert all(v["error_type"] == "ArgumentError" for v in d["stacks"].values())


def test_unknown_tool(env):
    r = rpc(env, "tools/call", {"name": "configure_interface", "arguments": {}})
    body = r.json()
    assert "error" in body or body["result"].get("isError") is True


def test_audit_log(env):
    lines = [json.loads(x) for x in (env["tmp"] / "audit.jsonl").read_text().splitlines()]
    assert lines and all(x["client"] == "aios" for x in lines)
    assert all(c.split(": ", 1)[1].startswith("show ") for x in lines for c in x["commands"])
    assert any(c.startswith("core-b: ") for x in lines for c in x["commands"])
    mac = [x for x in lines if x["tool"] == "find_mac" and x["status"] == "ok"]
    assert mac and mac[0]["args"]["mac"] == "00:90:FA:11:22:33"
    bad = [x for x in lines if x["tool"] == "get_interface_detail" and x["status"] == "error"]
    assert bad and all(x["commands"] == [] for x in bad)
    assert any(x["stack"] == "all" and "core-a:" in (x["error"] or "") for x in bad)
