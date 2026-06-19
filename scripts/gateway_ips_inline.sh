#!/bin/bash

# =========================================================
# GATEWAY IPS INLINE MODE
#
# Purpose:
# - Used for Snort IPS demo
# - Selected traffic goes to NFQUEUE
# - Snort IPS can block/drop malicious traffic
# =========================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/config_firewall" ips
