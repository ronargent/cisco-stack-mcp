#!/usr/bin/env bash
# =============================================================================
# cisco-stack-mcp installer for Ubuntu 26.04 (x86_64 or s390x)
#
#   sudo ./deploy/install.sh                 # interactive
#   sudo NONINTERACTIVE=1 CSM_SSH_PASSWORD=... ./deploy/install.sh
#
# Safe to re-run: existing config, secrets, tokens and TLS files are kept.
# Settings (env overrides):
#   INSTALL_DIR=/opt/cisco-stack-mcp   CONF_DIR=/etc/cisco-stack-mcp
#   LOG_DIR=/var/log/cisco-stack-mcp   SVC_USER=cisco-mcp
#   MCP_PORT=8002 (localhost only)     TLS_PORT=8443 (nginx, public)
#   SERVER_NAME=$(hostname -f)         TLS_CERT= TLS_KEY= (use an existing cert)
#   PYTHON_VERSION=3.13
# =============================================================================
set -euo pipefail
umask 022   # lesson from the Zabbix build: a hardened root umask left files unreadable

INSTALL_DIR="${INSTALL_DIR:-/opt/cisco-stack-mcp}"
CONF_DIR="${CONF_DIR:-/etc/cisco-stack-mcp}"
LOG_DIR="${LOG_DIR:-/var/log/cisco-stack-mcp}"
SVC_USER="${SVC_USER:-cisco-mcp}"
MCP_PORT="${MCP_PORT:-8002}"
TLS_PORT="${TLS_PORT:-8443}"
SERVER_NAME="${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}"
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"
PYTHON_VERSION="${PYTHON_VERSION:-3.13}"
NONINTERACTIVE="${NONINTERACTIVE:-0}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

# Prompts never abort the script on empty input or EOF (lesson from the Zabbix installer).
ask() {  # ask "question" "default" -> echoes answer
  local answer=""
  if [[ "$NONINTERACTIVE" == "1" ]]; then echo "$2"; return 0; fi
  read -r -p "$1 [$2] " answer || true
  echo "${answer:-$2}"
}
yes_no() {  # yes_no "question" "y|n"
  local a; a="$(ask "$1 (y/n)" "$2")"
  [[ "${a,,}" == y* ]]
}

[[ $EUID -eq 0 ]] || die "run as root: sudo $0"
[[ -f "$SRC_DIR/pyproject.toml" && -d "$SRC_DIR/cisco_stack_mcp" ]] || die "run from the unpacked cisco-stack-mcp directory"

. /etc/os-release 2>/dev/null || true
[[ "${VERSION_ID:-}" == "26.04" ]] || warn "tested on Ubuntu 26.04; this is ${PRETTY_NAME:-unknown}"

port_owner="$(ss -ltnpH "sport = :$MCP_PORT" 2>/dev/null || true)"
if [[ -n "$port_owner" ]] && ! grep -q 'cisco-stack-mcp' <<<"$port_owner" && ! systemctl is-active --quiet cisco-stack-mcp; then
  die "port $MCP_PORT is already in use (Zabbix MCP?). Re-run with MCP_PORT=<free port>"
fi

# --- 1. packages ------------------------------------------------------------------
info "Installing OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv nginx openssl openssh-client curl >/dev/null

# --- 2. service user --------------------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
  info "Creating service user $SVC_USER"
  useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

# --- 3. application ---------------------------------------------------------------
info "Installing application to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/app"
rm -rf "$INSTALL_DIR/app.new"
mkdir -p "$INSTALL_DIR/app.new"
cp -r "$SRC_DIR"/{cisco_stack_mcp,config,deploy,scripts,pyproject.toml,requirements.lock,README.md} "$INSTALL_DIR/app.new/"
find "$INSTALL_DIR/app.new" -name '__pycache__' -prune -exec rm -rf {} +
rm -rf "$INSTALL_DIR/app"
mv "$INSTALL_DIR/app.new" "$INSTALL_DIR/app"
chmod +x "$INSTALL_DIR/app/scripts/"*.sh "$INSTALL_DIR/app/deploy/install.sh"

info "Building Python $PYTHON_VERSION environment"
UV=""
if command -v uv >/dev/null 2>&1; then
  UV="$(command -v uv)"
else
  python3 -m venv "$INSTALL_DIR/bootstrap"
  "$INSTALL_DIR/bootstrap/bin/pip" install -q --upgrade uv && UV="$INSTALL_DIR/bootstrap/bin/uv" \
    || warn "could not install uv; falling back to the system Python"
fi
rm -rf "$INSTALL_DIR/venv"
if [[ -n "$UV" ]] && UV_PYTHON_INSTALL_DIR="$INSTALL_DIR/python" "$UV" venv -q -p "$PYTHON_VERSION" "$INSTALL_DIR/venv"; then
  UV_PYTHON_INSTALL_DIR="$INSTALL_DIR/python" "$UV" pip install -q --python "$INSTALL_DIR/venv/bin/python" \
    -r "$INSTALL_DIR/app/requirements.lock" "$INSTALL_DIR/app"
else
  warn "uv-managed Python $PYTHON_VERSION unavailable; using system $(python3 --version)"
  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/app/requirements.lock" "$INSTALL_DIR/app" \
    || "$INSTALL_DIR/venv/bin/pip" install -q "$INSTALL_DIR/app"
fi
chmod -R a+rX "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "import cisco_stack_mcp.server" || die "application import failed"

# --- 4. configuration ---------------------------------------------------------------
info "Configuration in $CONF_DIR"
install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
if [[ ! -f "$CONF_DIR/stacks.yaml" ]]; then
  install -m 0640 -o root -g "$SVC_USER" "$INSTALL_DIR/app/config/stacks.example.yaml" "$CONF_DIR/stacks.yaml"
  warn "created $CONF_DIR/stacks.yaml from the example: edit the IPs before use"
  if [[ "$NONINTERACTIVE" != "1" ]]; then
    a="$(ask "Stack A name" "core-a")"; ha="$(ask "Stack A management IP" "10.223.99.11")"
    b="$(ask "Stack B name (blank for none)" "core-b")"; hb=""
    [[ -n "$b" ]] && hb="$(ask "Stack B management IP" "10.223.99.12")"
    {
      echo "stacks:"
      echo "  - name: $a"; echo "    host: $ha"; echo "    site: DC1"; echo "    expected_members: 2"
      if [[ -n "$b" ]]; then
        echo "  - name: $b"; echo "    host: $hb"; echo "    site: DC1"; echo "    expected_members: 2"
      fi
    } > "$CONF_DIR/stacks.yaml"
  fi
fi
chown root:"$SVC_USER" "$CONF_DIR/stacks.yaml"; chmod 0640 "$CONF_DIR/stacks.yaml"
"$INSTALL_DIR/venv/bin/python" -c "from cisco_stack_mcp.inventory import Inventory; i=Inventory.load('$CONF_DIR/stacks.yaml'); print('   stacks:', ', '.join(i.names()))" \
  || die "$CONF_DIR/stacks.yaml is invalid"

cat > "$CONF_DIR/server.env" <<EOF
# Non-secret settings for cisco-stack-mcp (rewritten by install.sh)
CSM_INVENTORY=$CONF_DIR/stacks.yaml
CSM_TOKENS_FILE=$CONF_DIR/tokens.json
CSM_KNOWN_HOSTS=$CONF_DIR/known_hosts
CSM_AUDIT_LOG=$LOG_DIR/audit.jsonl
CSM_HOST=127.0.0.1
CSM_PORT=$MCP_PORT
CSM_SSH_USERNAME=${CSM_SSH_USERNAME:-mcp-ro}
CSM_CACHE_TTL=30
CSM_IDLE_TIMEOUT=300
CSM_RATE_LIMIT=30
CSM_MAX_ROWS=500
CSM_LOG_LEVEL=INFO
EOF
chown root:"$SVC_USER" "$CONF_DIR/server.env"; chmod 0640 "$CONF_DIR/server.env"

if [[ ! -s "$CONF_DIR/secrets.env" ]] || grep -q '^CSM_SSH_PASSWORD=""$' "$CONF_DIR/secrets.env"; then
  pw="${CSM_SSH_PASSWORD:-}"
  if [[ -z "$pw" && "$NONINTERACTIVE" != "1" ]]; then
    read -r -s -p "Password for switch user mcp-ro (input hidden, blank to set later): " pw || true; echo
  fi
  esc="${pw//\\/\\\\}"; esc="${esc//\"/\\\"}"
  ( umask 027; printf 'CSM_SSH_PASSWORD="%s"\n' "$esc" > "$CONF_DIR/secrets.env" )
  unset pw esc
fi
chown root:"$SVC_USER" "$CONF_DIR/secrets.env"; chmod 0640 "$CONF_DIR/secrets.env"

if [[ ! -f "$CONF_DIR/tokens.json" ]]; then
  echo '{"clients": {}}' > "$CONF_DIR/tokens.json"
fi
chown root:"$SVC_USER" "$CONF_DIR/tokens.json"; chmod 0640 "$CONF_DIR/tokens.json"
[[ -f "$CONF_DIR/known_hosts" ]] || install -m 0644 -o root -g "$SVC_USER" /dev/null "$CONF_DIR/known_hosts"

cat > /usr/local/bin/cisco-stack-mcp-token <<EOF
#!/bin/sh
# Manage client tokens: cisco-stack-mcp-token add|rotate|revoke|list <client>
[ "\$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
CSM_TOKENS_FILE=$CONF_DIR/tokens.json exec $INSTALL_DIR/venv/bin/cisco-stack-mcp-token "\$@"
EOF
chmod 0755 /usr/local/bin/cisco-stack-mcp-token

# --- 5. logs ------------------------------------------------------------------------
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$LOG_DIR"
cat > /etc/logrotate.d/cisco-stack-mcp <<EOF
$LOG_DIR/*.jsonl {
    weekly
    rotate 26
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su $SVC_USER $SVC_USER
}
EOF

# --- 6. systemd ---------------------------------------------------------------------
info "Installing systemd unit"
sed -e "s#/opt/cisco-stack-mcp#$INSTALL_DIR#g" -e "s#/etc/cisco-stack-mcp#$CONF_DIR#g" \
    -e "s#/var/log/cisco-stack-mcp#$LOG_DIR#g" -e "s#^User=cisco-mcp#User=$SVC_USER#" \
    -e "s#^Group=cisco-mcp#Group=$SVC_USER#" \
    "$INSTALL_DIR/app/deploy/cisco-stack-mcp.service" > /etc/systemd/system/cisco-stack-mcp.service
systemctl daemon-reload
systemctl enable -q cisco-stack-mcp

# --- 7. TLS + nginx -----------------------------------------------------------------
info "Configuring TLS and nginx on port $TLS_PORT"
install -d -m 0750 -o root -g root "$CONF_DIR/tls"
if [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]]; then
  CERT="$TLS_CERT"; KEY="$TLS_KEY"
else
  CERT="$CONF_DIR/tls/server.crt"; KEY="$CONF_DIR/tls/server.key"
  if [[ ! -s "$CERT" || ! -s "$KEY" ]]; then
    san="DNS:$SERVER_NAME,DNS:$(hostname),DNS:localhost,IP:127.0.0.1"
    for ip in $(hostname -I 2>/dev/null); do san="$san,IP:$ip"; done
    ( umask 077
      openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -keyout "$KEY" -out "$CERT" \
        -subj "/CN=$SERVER_NAME/O=TES cisco-stack-mcp" -addext "subjectAltName=$san" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,digitalSignature,keyCertSign" \
        >/dev/null 2>&1 )
    chmod 0644 "$CERT"
    warn "generated a self-signed certificate: clients must trust $CERT"
  fi
fi

cat > /etc/nginx/conf.d/cisco-stack-mcp-ratelimit.conf <<EOF
limit_req_zone \$binary_remote_addr zone=cisco_stack_mcp:1m rate=5r/s;
EOF
LISTEN6=""
if [[ -s /proc/net/if_inet6 ]]; then LISTEN6="listen [::]:$TLS_PORT ssl;"; fi
cat > /etc/nginx/sites-available/cisco-stack-mcp <<EOF
# cisco-stack-mcp: TLS front end (generated by install.sh)
server {
    listen $TLS_PORT ssl;
    $LISTEN6
    server_name $SERVER_NAME _;

    ssl_certificate     $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 1m;
    access_log /var/log/nginx/cisco-stack-mcp.access.log;
    error_log  /var/log/nginx/cisco-stack-mcp.error.log;

    location = /mcp {
        limit_req zone=cisco_stack_mcp burst=20 nodelay;
        proxy_pass http://127.0.0.1:$MCP_PORT/mcp;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
    location = /health {
        proxy_pass http://127.0.0.1:$MCP_PORT/health;
    }
    location / {
        return 404;
    }
}
EOF
ln -sf /etc/nginx/sites-available/cisco-stack-mcp /etc/nginx/sites-enabled/cisco-stack-mcp
if ! nginx -t -q; then
  # Never leave a broken site enabled: other sites on this nginx (e.g. the Zabbix MCP) would fail on next reload.
  rm -f /etc/nginx/sites-enabled/cisco-stack-mcp /etc/nginx/conf.d/cisco-stack-mcp-ratelimit.conf
  die "nginx config test failed (see above); the cisco-stack-mcp site was disabled and nothing was reloaded"
fi
systemctl enable -q nginx
systemctl reload nginx || systemctl restart nginx

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  warn "ufw is active: allow clients with e.g.  ufw allow from <aios-ip> to any port $TLS_PORT proto tcp"
fi

# --- 8. host keys + start -------------------------------------------------------------
if [[ ! -s "$CONF_DIR/known_hosts" ]]; then
  info "Collecting switch SSH host keys"
  export CONF_DIR INSTALL_DIR SVC_USER
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    "$INSTALL_DIR/app/scripts/refresh-host-keys.sh" --yes \
      || warn "host keys not collected; run $INSTALL_DIR/app/scripts/refresh-host-keys.sh once the switches are reachable"
  else
    "$INSTALL_DIR/app/scripts/refresh-host-keys.sh" \
      || warn "host keys not saved; run $INSTALL_DIR/app/scripts/refresh-host-keys.sh later"
  fi
fi

if grep -q '^CSM_SSH_PASSWORD=""$' "$CONF_DIR/secrets.env"; then
  warn "switch password not set: edit $CONF_DIR/secrets.env, then: systemctl start cisco-stack-mcp"
else
  info "Starting cisco-stack-mcp"
  systemctl restart cisco-stack-mcp
  ok=0
  for _ in $(seq 1 20); do
    if curl -sf --cacert "$CERT" --resolve "$SERVER_NAME:$TLS_PORT:127.0.0.1" "https://$SERVER_NAME:$TLS_PORT/health" >/dev/null 2>&1 \
       || curl -sfk "https://127.0.0.1:$TLS_PORT/health" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [[ $ok -eq 1 ]]; then info "Health check OK"; else warn "service not healthy yet: journalctl -u cisco-stack-mcp -n 50"; fi
fi

# --- 9. first client token -------------------------------------------------------------
if [[ "$NONINTERACTIVE" != "1" ]] && ! grep -q '"aios"' "$CONF_DIR/tokens.json"; then
  if yes_no "Create a token for the AIOS client now?" "y"; then
    /usr/local/bin/cisco-stack-mcp-token add aios
  fi
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

----------------------------------------------------------------------------
 cisco-stack-mcp installed
   MCP endpoint : https://${IP:-$SERVER_NAME}:$TLS_PORT/mcp   (Streamable HTTP, bearer token)
   Health       : https://${IP:-$SERVER_NAME}:$TLS_PORT/health
   Trust cert   : $CERT
   Inventory    : $CONF_DIR/stacks.yaml
   Audit log    : $LOG_DIR/audit.jsonl
   Tokens       : sudo cisco-stack-mcp-token add|rotate|revoke|list <client>
   Host keys    : sudo $INSTALL_DIR/app/scripts/refresh-host-keys.sh
   Smoke test   : MCP_TOKEN=<token> $INSTALL_DIR/app/scripts/smoke-test.sh https://127.0.0.1:$TLS_PORT $CERT
----------------------------------------------------------------------------
EOF
