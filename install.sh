#!/bin/bash
set -euo pipefail

# Bline-X Agent Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/DJR-FP/blinex-agent/main/install.sh | \
#     BLINEX_SETUP_KEY=<key> BLINEX_MANAGEMENT_URL=<host:50051> BLINEX_SIGNAL_URL=<host:10000> sudo -E bash

BLINEX_SETUP_KEY="${BLINEX_SETUP_KEY:-}"
BLINEX_MANAGEMENT_URL="${BLINEX_MANAGEMENT_URL:-localhost:50051}"
BLINEX_SIGNAL_URL="${BLINEX_SIGNAL_URL:-localhost:10000}"
BLINEX_RELAY_URL="${BLINEX_RELAY_URL:-}"
BLINEX_TURN_USER="${BLINEX_TURN_USER:-blinex}"
BLINEX_TURN_PASS="${BLINEX_TURN_PASS:-}"
BLINEX_WG_IFACE="${BLINEX_WG_IFACE:-blinex0}"
BLINEX_STATE_DIR="${BLINEX_STATE_DIR:-/var/lib/blinex}"
BLINEX_INSTALL_DIR="${BLINEX_INSTALL_DIR:-/usr/local/bin}"
BLINEX_SERVICE_DIR="${BLINEX_SERVICE_DIR:-/etc/systemd/system}"
GITHUB_REPO="DJR-FP/blinex-agent"
VERSION="${BLINEX_VERSION:-latest}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[blinex]${NC} $*"; }
warn()  { echo -e "${YELLOW}[blinex]${NC} $*"; }
error() { echo -e "${RED}[blinex]${NC} $*" >&2; exit 1; }

# Checks
[[ $EUID -ne 0 ]] && error "Please run as root (sudo $0)"
[[ -z "$BLINEX_SETUP_KEY" ]] && error "BLINEX_SETUP_KEY is required"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="arm"   ;;
  *)       error "Unsupported architecture: $ARCH" ;;
esac

info "Installing Bline-X agent ($OS/$ARCH)…"

# Install WireGuard tools if missing
if ! command -v wg &>/dev/null; then
  warn "Installing WireGuard tools…"
  if command -v apt-get &>/dev/null; then
    apt-get install -y wireguard-tools
  elif command -v dnf &>/dev/null; then
    dnf install -y wireguard-tools
  elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm wireguard-tools
  else
    warn "Could not install WireGuard tools automatically. Please install them manually."
  fi
fi

# Download binary
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
  [[ -z "$VERSION" ]] && error "Could not determine latest version"
fi
info "Version: ${VERSION}"
BINARY_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/blinex-agent-${OS}-${ARCH}"
info "Downloading agent from ${BINARY_URL}…"
curl -fsSL -o /tmp/blinex-agent "${BINARY_URL}" || {
  warn "GitHub release not found. Building from source is required for now."
  warn "See: https://github.com/${GITHUB_REPO}#building"
  exit 1
}
chmod +x /tmp/blinex-agent
mv /tmp/blinex-agent "${BLINEX_INSTALL_DIR}/blinex-agent"

# Create state and config dirs
mkdir -p "${BLINEX_STATE_DIR}" /etc/blinex

# Build STUN/TURN URL list
MGMT_HOST=$(echo "${BLINEX_MANAGEMENT_URL}" | cut -d: -f1)
STUN_URLS="\"stun:stun.l.google.com:19302\""
if [ -n "${BLINEX_RELAY_URL}" ]; then
  STUN_URLS="${STUN_URLS}, \"turn:${BLINEX_RELAY_URL}?transport=udp\""
elif [ "${MGMT_HOST}" != "localhost" ]; then
  STUN_URLS="${STUN_URLS}, \"turn:${MGMT_HOST}:3478?transport=udp\""
fi

# Write config
cat > /etc/blinex/agent.json <<EOF
{
  "management_url": "${BLINEX_MANAGEMENT_URL}",
  "signal_url": "${BLINEX_SIGNAL_URL}",
  "setup_key": "${BLINEX_SETUP_KEY}",
  "wg_interface": "${BLINEX_WG_IFACE}",
  "state_dir": "${BLINEX_STATE_DIR}",
  "stun_urls": [${STUN_URLS}],
  "turn_user": "${BLINEX_TURN_USER}",
  "turn_pass": "${BLINEX_TURN_PASS}",
  "tls_skip_verify": true
}
EOF
chmod 600 /etc/blinex/agent.json

# Write systemd service
if command -v systemctl &>/dev/null; then
  cat > "${BLINEX_SERVICE_DIR}/blinex-agent.service" <<EOF
[Unit]
Description=Bline-X Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BLINEX_INSTALL_DIR}/blinex-agent -config /etc/blinex/agent.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now blinex-agent
  info "Agent installed and started as blinex-agent.service"
  info "Check status: systemctl status blinex-agent"
  info "View logs:    journalctl -u blinex-agent -f"
elif [ "$OS" = "darwin" ]; then
  PLIST="/Library/LaunchDaemons/io.blinex.agent.plist"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.blinex.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BLINEX_INSTALL_DIR}/blinex-agent</string>
    <string>-config</string>
    <string>/etc/blinex/agent.json</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/blinex-agent.log</string>
  <key>StandardOutPath</key><string>/var/log/blinex-agent.log</string>
</dict>
</plist>
EOF
  launchctl load "$PLIST"
  info "Agent installed and started as io.blinex.agent"
  info "View logs: tail -f /var/log/blinex-agent.log"
else
  info "Systemd not found. Start manually:"
  info "  sudo ${BLINEX_INSTALL_DIR}/blinex-agent -config /etc/blinex/agent.json"
fi

info "Done! Your device will appear in the dashboard once connected."
info "To uninstall: curl -fsSL https://raw.githubusercontent.com/DJR-FP/blinex-agent/main/uninstall.sh | sudo bash"
