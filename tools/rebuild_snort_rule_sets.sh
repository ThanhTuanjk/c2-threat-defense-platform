#!/bin/bash

RULE_DIR="/usr/local/etc/rules"

LOCAL_IDS="${RULE_DIR}/local_ids.rules"
LOCAL_IPS="${RULE_DIR}/local_ips.rules"

LOCAL_AUTO_IPS="${RULE_DIR}/local_auto.rules"
LOCAL_AUTO_IDS="${RULE_DIR}/local_auto_ids.rules"

ACTIVE_IDS="${RULE_DIR}/active_ids.rules"
ACTIVE_IPS="${RULE_DIR}/active_ips.rules"

echo "[+] Rebuilding Snort IDS/IPS rule sets"

mkdir -p "$RULE_DIR"

touch "$LOCAL_IDS"
touch "$LOCAL_IPS"
touch "$LOCAL_AUTO_IPS"
touch "$LOCAL_AUTO_IDS"

# =========================================================
# Build IDS auto rules from IPS auto rules
# Convert:
#   drop tcp ...  -> alert tcp ...
#   block tcp ... -> alert tcp ...
# =========================================================

sed -E \
    -e 's/^(drop|block) /alert /' \
    -e 's/AUTO-ZEEK block/AUTO-ZEEK alert/g' \
    "$LOCAL_AUTO_IPS" > "$LOCAL_AUTO_IDS"

# =========================================================
# Build active IDS and active IPS rules
# =========================================================

cat "$LOCAL_IDS" "$LOCAL_AUTO_IDS" > "$ACTIVE_IDS"
cat "$LOCAL_IPS" "$LOCAL_AUTO_IPS" > "$ACTIVE_IPS"

echo "[OK] Built:"
echo "  IDS: $ACTIVE_IDS"
echo "  IPS: $ACTIVE_IPS"
