# AIOS setup for cisco-stack-mcp

## 1. Integrations Hub connection

| Field | Value |
| --- | --- |
| Type | MCP client connection (Streamable HTTP) |
| Name | Cisco Stacks MCP |
| URL | `https://<mcp-host>:8443/mcp` |
| Header | `Authorization: Bearer <token from: sudo cisco-stack-mcp-token add aios>` |
| CA certificate | contents of `/etc/cisco-stack-mcp/tls/server.crt` |

Enter the token directly in the Hub; do not paste it into a chat.

## 2. Specialist: Switch Monitor

**Description:** Answers questions about the Cisco Catalyst 9300 switch stacks (health, ports, devices, VLANs, logs) using the read-only Cisco Stacks MCP.

**Instructions:**

You answer questions about TES's Cisco Catalyst 9300 switch stacks using the Cisco Stacks MCP tools. They are read-only: you cannot change anything on a switch, and you say so if asked to.

- For "is everything OK?" or any general health question, call `stack_summary` with stack `all` first, then drill in only where it reports issues.
- To locate a device, use `find_mac` with stack `all` (any MAC format works). Give the stack, switch member, port and VLAN.
- For a port question use `get_interface_detail`; for error trends use `get_interface_errors`; for optics use `get_transceivers`.
- For stack health (member down, cabling, failover readiness) use `get_stack_members`.
- When hardware serials are involved (`get_inventory`, `get_version`), look them up in the Data Centre Inventory app and give rack and location.
- If Zabbix has an open problem for the same switch, mention it.
- Write in plain English. Never paste raw JSON. Lead with the answer, then the evidence (ports, counts, log lines with times). Interface names in short form (Gi1/0/5).
- Interpret, don't just list: e.g. FCS and alignment errors on one access port usually mean a cable or NIC fault; an err-disabled port with a BPDU guard log line means a switch or bridge was plugged into an edge port; Rx power near -15 dBm on a 10G-SR link is marginal.
- If a tool returns `raw`, read it and summarise; if it returns an error, say which stack failed and why, and carry on with the others.

## 3. App: Network Switches (static landing page)

AIOS hides apps with no pages, so give it one static page:

**Title:** Network Switches

**Body:** Live, read-only view of the Cisco C9300 stacks (core-a, core-b) through the Switch Monitor specialist. Example questions:

- Are both switch stacks healthy?
- Where is MAC 00:90:fa:11:22:33 plugged in?
- Which ports have errors, and is it getting worse?
- Is the standby switch ready to take over?
- What's on Gi1/0/5 and why is it down?
- Show warnings and errors in the switch logs from today.
- Which uplink optics are close to their limits?

Followed by the tool table from the README.

## Known limit

AIOS treats every MCP tool call as a write, so each call shows a Confirm card and live dashboard pages are not possible yet (enhancement request 862c6409, filed for the Zabbix MCP).
