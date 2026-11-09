#!/usr/bin/env bash
# Collect SSH host keys for every stack in stacks.yaml into /etc/cisco-stack-mcp/known_hosts.
# The server verifies switch host keys against this file (CSM_KNOWN_HOSTS).
# Usage: sudo refresh-host-keys.sh [--yes]
set -euo pipefail
umask 022

CONF_DIR="${CONF_DIR:-/etc/cisco-stack-mcp}"
INSTALL_DIR="${INSTALL_DIR:-/opt/cisco-stack-mcp}"
SVC_USER="${SVC_USER:-cisco-mcp}"
PY="${INSTALL_DIR}/venv/bin/python"
ASSUME_YES=0
[[ "${1:-}" == "--yes" ]] && ASSUME_YES=1

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
[[ -x "$PY" ]] || PY=python3

mapfile -t ENTRIES < <("$PY" - "$CONF_DIR/stacks.yaml" <<'EOF'
import sys, yaml
for s in (yaml.safe_load(open(sys.argv[1])) or {}).get("stacks") or []:
    print(f"{s['name']} {s['host']} {s.get('port') or 22}")
EOF
)

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
failed=0
for e in "${ENTRIES[@]}"; do
  read -r name host port <<<"$e"
  echo "== $name ($host:$port)"
  if out="$(ssh-keyscan -T 5 -p "$port" -t ed25519,ecdsa,rsa "$host" 2>/dev/null)" && [[ -n "$out" ]]; then
    printf '%s\n' "$out" >> "$tmp"
    printf '%s\n' "$out" | ssh-keygen -lf - | sed 's/^/   /'
  else
    echo "   !! no host key from $host:$port (unreachable, wrong IP, or SSH not enabled)"
    failed=1
  fi
done

if [[ ! -s "$tmp" ]]; then
  echo "No keys collected; known_hosts left unchanged."
  exit 1
fi

if [[ $ASSUME_YES -ne 1 ]]; then
  echo
  echo "Compare these fingerprints with each switch ('show ip ssh' / 'show crypto key mypubkey')."
  ans=""
  read -r -p "Trust and save them? [y/N] " ans || true
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || { echo "Not saved."; exit 1; }
fi

install -m 0644 -o root -g "$SVC_USER" "$tmp" "$CONF_DIR/known_hosts"
echo "Saved $CONF_DIR/known_hosts"
[[ $failed -eq 0 ]] || echo "Warning: some stacks had no key; the server will refuse to connect to them until this is re-run."
systemctl is-active --quiet cisco-stack-mcp && systemctl restart cisco-stack-mcp && echo "Service restarted." || true
