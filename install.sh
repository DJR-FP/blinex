#!/bin/bash
set -euo pipefail

# Meshnet Agent Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/DJR-FP/meshagent/main/install.sh | sudo MESHNET_SETUP_KEY=<key> bash
# Or:    sudo MESHNET_SETUP_KEY=<key> MESHNET_MANAGEMENT_URL=<host:50051> ./install.sh

MESHNET_SETUP_KEY="${MESHNET_SETUP_KEY:-}"
MESHNET_MANAGEMENT_URL="${MESHNET_MANAGEMENT_URL:-localhost:50051}"
MESHNET_SIGNAL_URL="${MESHNET_SIGNAL_URL:-localhost:10000}"
MESHNET_WG_IFACE="${MESHNET_WG_IFACE:-meshnet0}"
MESHNET_STATE_DIR="${MESHNET_STATE_DIR:-/var/lib/meshnet}"
MESHNET_INSTALL_DIR="${MESHNET_INSTALL_DIR:-/usr/local/bin}"
MESHNET_SERVICE_DIR="${MESHNET_SERVICE_DIR:-/etc/systemd/system}"
GITHUB_REPO="DJR-FP/meshagent"
VERSION="${MESHNET_VERSION:-latest}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[meshnet]${NC} $*"; }
warn()  { echo -e "${YELLOW}[meshnet]${NC} $*"; }
error() { echo -e "${RED}[meshnet]${NC} $*" >&2; exit 1; }

# Checks
[[ $EUID -ne 0 ]] && error "Please run as root (sudo $0)"
[[ -z "$MESHNET_SETUP_KEY" ]] && error "MESHNET_SETUP_KEY is required"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="arm"   ;;
  *)       error "Unsupported architecture: $ARCH" ;;
esac

info "Installing Meshnet agent ($OS/$ARCH)…"

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
BINARY_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/meshnet-agent-${OS}-${ARCH}"
info "Downloading agent from ${BINARY_URL}…"
curl -fsSL -o /tmp/meshnet-agent "${BINARY_URL}" || {
  warn "GitHub release not found. Building from source is required for now."
  warn "See: https://github.com/${GITHUB_REPO}#building"
  exit 1
}
chmod +x /tmp/meshnet-agent
mv /tmp/meshnet-agent "${MESHNET_INSTALL_DIR}/meshnet-agent"

# Create state and config dirs
mkdir -p "${MESHNET_STATE_DIR}" /etc/meshnet

# Write config
cat > /etc/meshnet/agent.json <<EOF
{
  "management_url": "${MESHNET_MANAGEMENT_URL}",
  "signal_url": "${MESHNET_SIGNAL_URL}",
  "setup_key": "${MESHNET_SETUP_KEY}",
  "wg_interface": "${MESHNET_WG_IFACE}",
  "state_dir": "${MESHNET_STATE_DIR}"
}
EOF
chmod 600 /etc/meshnet/agent.json

# Write systemd service
if command -v systemctl &>/dev/null; then
  cat > "${MESHNET_SERVICE_DIR}/meshnet-agent.service" <<EOF
[Unit]
Description=Meshnet Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${MESHNET_INSTALL_DIR}/meshnet-agent -config /etc/meshnet/agent.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now meshnet-agent
  info "Agent installed and started as meshnet-agent.service"
  info "Check status: systemctl status meshnet-agent"
  info "View logs:    journalctl -u meshnet-agent -f"
else
  info "Systemd not found. Start manually:"
  info "  ${MESHNET_INSTALL_DIR}/meshnet-agent -config /etc/meshnet/agent.json"
fi

info "Done! Your device will appear in the dashboard once connected."
