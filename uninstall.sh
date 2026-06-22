#!/bin/bash
set -euo pipefail

# Bline-X Agent Uninstaller
# Usage: curl -fsSL https://raw.githubusercontent.com/DJR-FP/blinex-agent/main/uninstall.sh | sudo bash
# Or:    sudo ./uninstall.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[blinex]${NC} $*"; }
warn()  { echo -e "${YELLOW}[blinex]${NC} $*"; }
error() { echo -e "${RED}[blinex]${NC} $*" >&2; exit 1; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "$OS" in
  linux)
    [[ $EUID -ne 0 ]] && error "Please run as root (sudo $0)"

    # Stop and disable systemd service
    if systemctl is-active --quiet blinex-agent 2>/dev/null; then
      info "Stopping blinex-agent service…"
      systemctl stop blinex-agent
    fi
    if systemctl is-enabled --quiet blinex-agent 2>/dev/null; then
      info "Disabling blinex-agent service…"
      systemctl disable blinex-agent
    fi
    if [ -f /etc/systemd/system/blinex-agent.service ]; then
      info "Removing systemd unit file…"
      rm -f /etc/systemd/system/blinex-agent.service
      systemctl daemon-reload
    fi

    # Remove iptables rules
    if iptables -L BLINEX-ACL -n &>/dev/null; then
      info "Cleaning up iptables rules…"
      iptables -D INPUT -i blinex0 -j BLINEX-ACL 2>/dev/null || true
      iptables -D FORWARD -i blinex0 -j BLINEX-ACL 2>/dev/null || true
      iptables -F BLINEX-ACL 2>/dev/null || true
      iptables -X BLINEX-ACL 2>/dev/null || true
    fi
    # Remove MASQUERADE rules for exit node / subnet routing
    iptables -t nat -S 2>/dev/null | grep -i blinex0 | while read -r rule; do
      iptables -t nat $(echo "$rule" | sed 's/^-A/-D/') 2>/dev/null || true
    done

    # Remove binary
    if [ -f /usr/local/bin/blinex-agent ]; then
      info "Removing agent binary…"
      rm -f /usr/local/bin/blinex-agent
    fi

    # Remove config and state
    if [ -d /etc/blinex ]; then
      info "Removing config directory (/etc/blinex)…"
      rm -rf /etc/blinex
    fi
    if [ -d /var/lib/blinex ]; then
      info "Removing state directory (/var/lib/blinex)…"
      rm -rf /var/lib/blinex
    fi

    # Remove WireGuard interface if still present
    if ip link show blinex0 &>/dev/null; then
      info "Removing blinex0 interface…"
      ip link delete blinex0 2>/dev/null || true
    fi

    info "Bline-X agent uninstalled from Linux."
    ;;

  darwin)
    [[ $EUID -ne 0 ]] && error "Please run as root (sudo $0)"

    PLIST="/Library/LaunchDaemons/io.blinex.agent.plist"

    # Unload and remove launchd service
    if launchctl list io.blinex.agent &>/dev/null 2>&1; then
      info "Stopping blinex-agent service…"
      launchctl unload "$PLIST" 2>/dev/null || true
    fi
    if [ -f "$PLIST" ]; then
      info "Removing launchd plist…"
      rm -f "$PLIST"
    fi

    # Remove binary
    if [ -f /usr/local/bin/blinex-agent ]; then
      info "Removing agent binary…"
      rm -f /usr/local/bin/blinex-agent
    fi

    # Remove config and state
    if [ -d /etc/blinex ]; then
      info "Removing config directory (/etc/blinex)…"
      rm -rf /etc/blinex
    fi
    if [ -d /var/lib/blinex ]; then
      info "Removing state directory (/var/lib/blinex)…"
      rm -rf /var/lib/blinex
    fi

    # Remove log file
    if [ -f /var/log/blinex-agent.log ]; then
      info "Removing log file…"
      rm -f /var/log/blinex-agent.log
    fi

    info "Bline-X agent uninstalled from macOS."
    ;;

  *)
    error "Unsupported OS: $OS. For Windows, use uninstall.ps1 instead."
    ;;
esac

info "Done. The device will remain listed in the dashboard until you remove it there."
