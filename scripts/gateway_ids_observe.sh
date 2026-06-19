#!/bin/bash

# =========================================================
# GATEWAY IDS OBSERVE MODE
#
# Purpose:
# - Used for Snort IDS demo
# - No NFQUEUE
# - No packet blocking
# - Traffic is allowed to reach INetSim
# =========================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/config_firewall" observe
