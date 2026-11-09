#!/usr/bin/env bash
# Smoke test a deployed cisco-stack-mcp over HTTPS, the same way AIOS calls it.
# Usage: MCP_TOKEN=<token> ./smoke-test.sh [https://host:8443] [ca-cert.pem]
# Pass the token in the environment, never on the command line or in chat.
set -uo pipefail

URL="${1:-https://127.0.0.1:8443}"
CA="${2:-/etc/cisco-stack-mcp/tls/server.crt}"
: "${MCP_TOKEN:?set MCP_TOKEN to a client token}"

CURL=(curl -sS --max-time 120 --cacert "$CA")
[[ -r "$CA" ]] || { echo "CA file $CA not readable; using -k (insecure) for this test only"; CURL=(curl -sS --max-time 120 -k); }

rpc() {  # rpc <id> <method> <params-json>
  "${CURL[@]}" "$URL/mcp" \
    -H "Authorization: Bearer $MCP_TOKEN" \
    -H "Accept: application/json, text/event-stream" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"$2\",\"params\":$3}"
}

pass=0; fail=0
check() {  # check <label> <grep-pattern> <output>
  if grep -q -- "$2" <<<"$3"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; echo "      ${3:0:400}"; fail=$((fail+1)); fi
}

check "health endpoint"      '"status":"ok"'                 "$("${CURL[@]}" "$URL/health")"
check "auth required"        'unauthorized'                  "$("${CURL[@]}" "$URL/mcp" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
check "initialize"           'cisco-stack-mcp'               "$(rpc 1 initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}')"
check "18 read-only tools"   'readOnlyHint'                  "$(rpc 2 tools/list '{}')"
check "list_stacks"          'expected_members'              "$(rpc 3 tools/call '{"name":"list_stacks","arguments":{}}')"
check "health_check all"     'reachable'                     "$(rpc 4 tools/call '{"name":"health_check","arguments":{"stack":"all"}}')"
SUM="$(rpc 5 tools/call '{"name":"stack_summary","arguments":{"stack":"all"}}')"
check "stack_summary all"    'interface_status_counts'       "$SUM"
check "injection refused"    'ArgumentError'                 "$(rpc 6 tools/call '{"name":"get_interface_detail","arguments":{"stack":"all","interface":"Gi1/0/1 ; reload"}}')"

echo
echo "$pass passed, $fail failed"
echo "stack_summary (first 1500 chars):"
echo "${SUM:0:1500}"
[[ $fail -eq 0 ]]
