#!/bin/bash
#
# Setup script for creating a kernel bridge for CDA bridge mode deployments.
#
# This script creates a kernel bridge that allows libvirt VMs to be on the
# same L2 network as physical hosts. The bridge uses the interface's MAC
# address so DHCP will assign the same IP.
#
# Usage:
#   ./setup-bridge.sh <interface> [bridge_name]
#
# Example:
#   ./setup-bridge.sh eno8303
#   ./setup-bridge.sh eno8303 br-cda-0
#
# WARNING: Network connectivity will be briefly interrupted.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ $# -lt 1 ]; then
    echo "Usage: $0 <interface> [bridge_name]"
    echo "Example: $0 eno8303"
    exit 1
fi

INTERFACE="$1"
BRIDGE_NAME="${2:-br-cda-0}"

if ! ip link show "$INTERFACE" &>/dev/null; then
    log_error "Interface $INTERFACE does not exist"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

if ip link show "$BRIDGE_NAME" &>/dev/null; then
    if ip link show "$INTERFACE" 2>/dev/null | grep -q "master $BRIDGE_NAME"; then
        log_info "Bridge $BRIDGE_NAME already exists with $INTERFACE as member"
        exit 0
    else
        log_error "Bridge $BRIDGE_NAME exists but $INTERFACE is not part of it"
        exit 1
    fi
fi

# Get MAC address from the interface
MAC_ADDRESS=$(ip link show "$INTERFACE" | grep -oP 'link/ether \K[^ ]+')
CURRENT_CONN=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | grep ":${INTERFACE}$" | cut -d: -f1 || true)

log_info "Creating bridge $BRIDGE_NAME with MAC $MAC_ADDRESS from $INTERFACE"
log_info "DHCP will assign the same IP as before"
echo ""
log_warn "WARNING: Network connectivity will be briefly interrupted!"
read -p "Continue? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Aborted."
    exit 0
fi

# Create bridge with same MAC as the interface
nmcli connection add type bridge ifname "$BRIDGE_NAME" con-name "$BRIDGE_NAME"
nmcli connection modify "$BRIDGE_NAME" bridge.stp no
nmcli connection modify "$BRIDGE_NAME" ethernet.cloned-mac-address "$MAC_ADDRESS"
nmcli connection modify "$BRIDGE_NAME" ipv4.method auto

# Add interface as slave
nmcli connection add type bridge-slave ifname "$INTERFACE" master "$BRIDGE_NAME" con-name "${BRIDGE_NAME}-slave"

# Activate bridge
log_info "Activating bridge..."
[ -n "$CURRENT_CONN" ] && nmcli connection down "$CURRENT_CONN" 2>/dev/null || true
nmcli connection up "$BRIDGE_NAME"

log_info "Bridge setup complete!"
ip addr show "$BRIDGE_NAME"
