#!/usr/bin/env bash
# Host firewall rules for the honeypot VM.
# Run with: sudo bash ufw-rules.sh
# Adjust ADMIN_NET to the network you administer the machine from.
set -euo pipefail

ADMIN_NET="172.16.174.0/24"   # local VMware NAT network (Mac <-> VM)

ufw default deny incoming
ufw default allow outgoing

# Real SSH (key-only) - reachable only from the admin network
ufw allow from "$ADMIN_NET" to any port 22 proto tcp

# Honeypot port - open to everyone (documentation only: Docker bypasses ufw, see README)
ufw allow 2222/tcp

ufw --force enable
ufw status verbose
