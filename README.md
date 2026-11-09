# cisco-stack-mcp

Read-only MCP server for Cisco Catalyst 9300 stacks (C9300-24T, IOS XE), built and deployed the same way as the Zabbix MCP server: Python + FastMCP, Streamable HTTP at `/mcp`, per-client bearer tokens, nginx TLS, systemd, Ubuntu 26.04.

AIOS (and Claude Code, or the Mac mini Ollama/Qwen stack) ask questions such as "are both stacks healthy?" or "where is MAC 00:90:fa:11:22:33 plugged in?"; the server answers by running a fixed set of `show` commands over SSH and returning parsed JSON.

```
AIOS / Claude Code / Mac mini ──HTTPS + token──▶ nginx :8443 ──▶ cisco-stack-mcp :8002 (localhost)
                                                                     │  fixed show-command allowlist
                                                                     │  parse (custom → ntc-templates → Genie → raw)
                                                                     │  JSON-lines audit log
                                                                     └──SSH as mcp-ro (parser view MCP-RO)──▶ stack core-a, core-b
```

## Read-only, in three layers

| Layer | Control |
| --- | --- |
| Switch | User `mcp-ro` is bound to parser view `MCP-RO`: `show` commands plus `terminal length/width` only. Even a compromised server cannot configure, clear or reload. VTY ACL limits SSH to the MCP host and the admin subnet. |
| Server | Every command is built from a fixed template and checked against an anchored allowlist (`cisco_stack_mcp/commands.py`) before it is sent. Arguments are validated (interface names, VLAN 1–4094, MAC formats); `|`, `;`, newlines and keywords such as `redirect`, `configure`, `reload` are refused. There is no raw-CLI tool. |
| Client | All 18 tools carry `readOnlyHint: true`. The AIOS `cisco_mcp` tool, if used, keeps the same write-name guard as `zabbix_mcp`. |

## Tools

All take `stack` = a name from `stacks.yaml` or `all` (default). With `all`, stacks are queried in parallel and results come back under `stacks.<name>`.

| Tool | Commands | Answers |
| --- | --- | --- |
| `list_stacks` | none | Configured stacks and the allowed command set |
| `health_check` | `show clock` | SSH reachable, login OK, latency |
| `stack_summary` | combines the tools below | One-call health: members, port counts, error ports, environment, severe log lines, `issues[]` |
| `get_stack_members` | `show switch`, `show switch stack-ports summary`, `show redundancy` | Roles, priorities, states, stack cables, SSO/standby; flags missing members and down stack ports |
| `get_stack_power` | `show stack-power` | Power-stack budget |
| `get_version` | `show version`, `show install summary` | Release, uptime, reload reason, serials, install state |
| `get_inventory` | `show inventory`, `show license summary` | PIDs and serials (for DCIM cross-check), licences |
| `get_environment` | `show environment all` | Fans, temperatures with thresholds, PSUs, RPS; unhealthy sensors |
| `get_interfaces` | `show interfaces status` (+ `show ip interface brief`) | Filter by `member`, `status`, `vlan`; status counts |
| `get_interface_detail` | `show interfaces <if>`, `… switchport` | Counters, rates, description, VLAN mode |
| `get_interface_errors` | `show interfaces counters errors` | Ports with non-zero error counters |
| `get_transceivers` | `show interfaces transceiver` | Uplink optics: Tx/Rx dBm, alarm/warning flags |
| `get_vlans` | `show vlan brief`, `show interfaces trunk` | VLANs, access ports, trunk VLAN lists |
| `find_mac` | `show mac address-table [address|interface|vlan]` | Where a device is plugged in (any MAC format) |
| `get_neighbors` | `show cdp/lldp neighbors detail` | Attached devices and uplinks |
| `get_spanning_tree` | `show spanning-tree summary`, `… root` | Mode, root bridges, blocking ports |
| `get_etherchannels` | `show etherchannel summary` | Bundles and member state, with problems flagged |
| `get_logs` | `show logging` | Recent syslog, filter by `max_severity` (0–7) and `contains` |

Responses are capped at 500 rows (`truncated: true` when cut). Output that cannot be parsed comes back as `raw` text rather than an error. Results are cached for 30 s per stack and command; one command at a time is sent to each stack.

## 1. Prepare the switches

Apply `deploy/switch-config.txt` on each stack's active switch (console session open), then run its four checks as `mcp-ro`. If TACACS+/ISE is in use, create the account there instead of locally.

## 2. Install on the MCP host

Copy the tarball to the host (e.g. rondevelopment1, 10.223.35.10, which already runs the Zabbix MCP server) and run:

```bash
tar xzf cisco-stack-mcp-1.0.0.tar.gz
cd cisco-stack-mcp
sudo ./deploy/install.sh
```

The installer asks for the two stacks' names and management IPs, the `mcp-ro` password (hidden; stored only in `/etc/cisco-stack-mcp/secrets.env`, mode 0640), shows each switch's SSH host-key fingerprint for you to confirm, and offers to create the `aios` token. Re-running it upgrades the code and keeps config, secrets, tokens and the certificate.

| Path | Purpose |
| --- | --- |
| `/opt/cisco-stack-mcp/{app,venv}` | Code and Python 3.13 environment |
| `/etc/cisco-stack-mcp/stacks.yaml` | Inventory (edit, then `systemctl restart cisco-stack-mcp`) |
| `/etc/cisco-stack-mcp/secrets.env` | `CSM_SSH_PASSWORD` |
| `/etc/cisco-stack-mcp/tokens.json` | Client token hashes |
| `/etc/cisco-stack-mcp/known_hosts` | Switch SSH host keys (verified on every connect) |
| `/etc/cisco-stack-mcp/tls/server.crt` | Self-signed certificate clients must trust |
| `/var/log/cisco-stack-mcp/audit.jsonl` | One line per tool call |

Defaults: service on `127.0.0.1:8002`, nginx TLS on `:8443`. If 8002 is taken (e.g. by the Zabbix MCP server), run `sudo MCP_PORT=8012 ./deploy/install.sh`. To reuse an existing certificate: `TLS_CERT=… TLS_KEY=…`.

Unattended: `sudo NONINTERACTIVE=1 CSM_SSH_PASSWORD='…' ./deploy/install.sh` (edit `stacks.yaml` first, or it is created from the example).

## 3. Client tokens

```bash
sudo cisco-stack-mcp-token add aios          # prints the token once
sudo cisco-stack-mcp-token add claude-code
sudo cisco-stack-mcp-token add mac-mini
sudo cisco-stack-mcp-token list
sudo cisco-stack-mcp-token rotate aios       # old token stops working immediately
sudo cisco-stack-mcp-token revoke mac-mini
```

Only SHA-256 hashes are stored. Put each token straight into the client's secret store; do not paste tokens or the switch password into chat.

## 4. Smoke test

```bash
read -rs MCP_TOKEN; export MCP_TOKEN
/opt/cisco-stack-mcp/app/scripts/smoke-test.sh https://127.0.0.1:8443 /etc/cisco-stack-mcp/tls/server.crt
```

It checks health, auth rejection, `initialize`, the 18 read-only tools, `health_check` and `stack_summary` on all stacks, and that an injection attempt is refused.

## 5. Connect AIOS

1. Integrations Hub → add an MCP client connection, e.g. **Cisco Stacks MCP**: URL `https://<host>:8443/mcp`, header `Authorization: Bearer <aios token>`, trust `/etc/cisco-stack-mcp/tls/server.crt`.
2. App **Network Switches** with a static landing page (example questions and the tool table above): AIOS hides apps with no pages from the sidebar.
3. Specialist **Switch Monitor**: answer in plain language, never paste raw JSON; start with `stack_summary`; cross-reference serials from `get_inventory` with the DCIM app for rack and location; mention matching Zabbix problems for the same host.
4. Known AIOS limit: every MCP tool call is treated as a write, so each shows a Confirm card and live dashboard pages are not possible. Same open enhancement request as Zabbix (report 862c6409).

Claude Code on the PC: add the server as an HTTP MCP server with the `claude-code` token and point `NODE_EXTRA_CA_CERTS` at a copy of `server.crt` (as was needed for the Zabbix server).

## 6. Monitoring and audit

* Zabbix: monitor the `cisco-stack-mcp` systemd service, `https://<host>:8443/health` (expect `"status":"ok"`) and the certificate expiry (825 days).
* Ship `/var/log/cisco-stack-mcp/audit.jsonl` to Wazuh. Each line has time, client, tool, arguments, stack, the exact commands sent, cache hits, status and duration. `find_mac` arguments are logged because MAC lookups can identify users' devices.
* Logs rotate weekly, 26 weeks kept.

ISO 27001 Annex A evidence: 5.15 access control (per-client tokens), 8.2 privileged access (show-only parser view), 8.15 logging (audit log), 8.20 network security (VTY ACL, TLS). Add a risk-register entry for the new management path.

## Development and tests

```bash
uv venv -p 3.13 .venv && . .venv/bin/activate
uv pip install -r requirements-dev.txt -e .
pytest -q          # 88 tests
```

`tests/mock_switch.py` is an SSH server that replays `tests/fixtures/<stack>/*.txt`; the end-to-end tests run the real server against it over HTTP exactly as AIOS does. `core-b`'s fixtures simulate a stack with a removed member and down stack ports.

**Before go-live, replace the fixtures with real output:** log in as `mcp-ro`, run each command in the tool table on each stack, save the output (with nothing sensitive) under `tests/fixtures/<stack>/<command with spaces as _ and / as _>.txt`, and re-run `pytest`. Any command whose real output does not parse will fail `test_every_fixture_parses_to_rows`; it still works in production, returning `raw` text.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `SwitchUnreachable … BadHostKey`/`not found in known_hosts` | Host key missing or changed: verify, then `sudo /opt/cisco-stack-mcp/app/scripts/refresh-host-keys.sh` |
| `CommandRejected … Check the MCP-RO parser view` | The view is missing a command (usually `terminal width` or a `show` sub-command) |
| `SwitchUnreachable … Authentication failed` | Wrong password in `secrets.env`, or AAA not pointing at local/TACACS as expected |
| `401 unauthorized` | Missing/rotated token, or `Bearer ` prefix missing |
| Timeouts on `show logging` / `show mac address-table` | Large output: raise `CSM_COMMAND_TIMEOUT` in `server.env` |
| Permission errors after manual edits | `sudo chown root:cisco-mcp /etc/cisco-stack-mcp/* && sudo chmod 0640 /etc/cisco-stack-mcp/*.{env,json,yaml}` |

`journalctl -u cisco-stack-mcp -f` shows the service log; nginx logs are `/var/log/nginx/cisco-stack-mcp.*.log`.

## Phase 2 (not in this release)

Masked `show running-config`, CPU/memory, running-vs-startup drift, and a guarded `show_command` escape hatch, each needing the parser view widened and a separate review.
