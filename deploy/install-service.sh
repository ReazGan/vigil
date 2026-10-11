#!/usr/bin/env bash
#
# Install vigil as a hardened systemd service on a Linux server.
#
# It captures live traffic on the default interface and serves the dashboard on
# 127.0.0.1:8089 only (never exposed to the internet). Reach it with an SSH
# tunnel from your own machine:
#
#     ssh -L 8089:127.0.0.1:8089 you@your-server
#     then open http://127.0.0.1:8089
#
# Run as root:  sudo bash install-service.sh
#
set -euo pipefail

REPO="https://github.com/ReazGan/vigil"
PREFIX="/opt/vigil"
DATA="/var/lib/vigil"
CONF="/etc/vigil"
PORT="8089"
# Keep the capture light on a busy box: connection openers, DNS and ICMP, plus
# plaintext HTTP for payload rules. Widen this in the unit file if you want more.
BPF="(tcp[tcpflags] & tcp-syn != 0) or tcp port 80 or tcp port 8080 or udp port 53 or icmp"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo bash install-service.sh" >&2
  exit 1
fi

echo "[1/6] Installing system packages..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip git tcpdump
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 python3-pip git tcpdump
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q python3 python3-pip git tcpdump
else
  echo "No supported package manager (apt/dnf/yum) found." >&2
  exit 1
fi

echo "[2/6] Creating service user and directories..."
if ! id vigil >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin vigil
fi
mkdir -p "$PREFIX" "$DATA" "$CONF"
chown vigil:vigil "$DATA"
chmod 750 "$CONF"

echo "[3/6] Installing vigil into a virtualenv..."
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip -q
"$PREFIX/venv/bin/pip" install -q "vigil[api] @ git+$REPO"

echo "[4/6] Writing configuration..."
if [ ! -f "$CONF/vigil.env" ]; then
  PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  cat > "$CONF/vigil.env" <<EOF
VIGIL_USER=admin
VIGIL_PASSWORD=$PASS
VIGIL_SECRET=$SECRET
EOF
  chmod 600 "$CONF/vigil.env"
  NEWPASS=1
else
  echo "    keeping existing $CONF/vigil.env"
  NEWPASS=0
fi

IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1)"
IFACE="${IFACE:-eth0}"
echo "    capturing on interface: $IFACE"

echo "[5/6] Installing systemd service..."
cat > /etc/systemd/system/vigil.service <<EOF
[Unit]
Description=vigil network intrusion detection
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vigil
Group=vigil
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
EnvironmentFile=$CONF/vigil.env
ExecStart=$PREFIX/venv/bin/vigil serve --iface $IFACE --bpf "$BPF" --host 127.0.0.1 --port $PORT --db $DATA/vigil.db
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

echo "[6/6] Starting service..."
systemctl daemon-reload
systemctl enable --now vigil >/dev/null 2>&1
sleep 2
systemctl --no-pager --lines=0 status vigil || true

echo
echo "========================================================================"
echo " vigil is running on 127.0.0.1:$PORT  (not exposed to the internet)"
echo
echo " View it from your own machine with an SSH tunnel:"
echo "     ssh -L $PORT:127.0.0.1:$PORT <user>@<this-server>"
echo "     then open http://127.0.0.1:$PORT"
echo
if [ "$NEWPASS" -eq 1 ]; then
  echo " Login:  admin / $PASS"
  echo " (also stored in $CONF/vigil.env)"
else
  echo " Login user 'admin', password is in $CONF/vigil.env"
fi
echo
echo " Logs:   journalctl -u vigil -f"
echo " Stop:   systemctl stop vigil      Remove: systemctl disable --now vigil"
echo "========================================================================"
