#!/bin/bash

# =========================================================
# TERMINAL 2 - SNORT IPS WATCHER
# Purpose:
# - Apply gateway IPS mode
# - Verify NFQUEUE
# - Validate active_ips.rules in INLINE NFQ mode
# - Start Snort IPS
# - Show pretty block/observe events
# =========================================================

SNORT_BIN="/usr/local/bin/snort"
DAQ_DIR="/usr/local/lib/daq"
SNORT_CONF="/usr/local/etc/snort/snort.lua"
IPS_RULE_FILE="/usr/local/etc/rules/active_ips.rules"

SNORT_LOG_DIR="/var/log/snort"
SNORT_STDOUT="${SNORT_LOG_DIR}/snort_ips_stdout.log"
SNORT_VALIDATE_LOG="${SNORT_LOG_DIR}/snort_rule_validate.log"

LAB_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo ~$LAB_USER)"
GATEWAY_SCRIPT="${USER_HOME}/c2-defense-lab/scripts/lab_gateway_rules.sh"

SNORT_PID=""
TAIL_PID=""
LAST_HASH=""

cleanup() {
    echo
    echo "[+] Stopping Snort IPS..."

    if [ -n "$SNORT_PID" ]; then
        kill "$SNORT_PID" 2>/dev/null || true
    fi

    if [ -n "$TAIL_PID" ]; then
        kill "$TAIL_PID" 2>/dev/null || true
    fi

    pkill -P $$ 2>/dev/null || true

    echo "[+] Stopped Snort IPS."
    exit 0
}

trap cleanup INT TERM

calc_hash() {
    if [ -f "$IPS_RULE_FILE" ]; then
        sha256sum "$IPS_RULE_FILE" | awk '{print $1}'
    else
        echo "missing"
    fi
}

check_nfqueue() {
    local rules
    rules="$(iptables -L FORWARD -v -n --line-numbers)"
    echo "$rules" | grep -q "NFQUEUE.*tcp" || return 1
    echo "$rules" | grep -q "NFQUEUE.*udp" || return 1
}

apply_gateway_ips() {
    echo
    echo "[STEP 1] Applying Gateway IPS mode"

    if [ ! -f "$GATEWAY_SCRIPT" ]; then
        echo "[ERROR] Gateway script not found:"
        echo "        $GATEWAY_SCRIPT"
        exit 1
    fi

    bash "$GATEWAY_SCRIPT" ips >/tmp/lab_gateway_ips_start.log 2>&1

    if check_nfqueue; then
        echo "[OK] NFQUEUE exists. Traffic can go through Snort IPS."
        iptables -L FORWARD -v -n --line-numbers | grep NFQUEUE
    else
        echo "[ERROR] NFQUEUE not found. IPS cannot block traffic."
        echo "Check gateway log:"
        echo "sudo cat /tmp/lab_gateway_ips_start.log"
        exit 1
    fi
}

validate_rules() {
    echo
    echo "[STEP 2] Validating Snort IPS rules"
    echo "[+] Rule file: $IPS_RULE_FILE"

    mkdir -p "$SNORT_LOG_DIR"

    "$SNORT_BIN" \
    --daq-dir "$DAQ_DIR" \
    -c "$SNORT_CONF" \
    -R "$IPS_RULE_FILE" \
    -Q --daq nfq --daq-var queue=0 \
    -T > "$SNORT_VALIDATE_LOG" 2>&1

    if [ $? -eq 0 ]; then
        echo "[OK] Snort IPS rule validation passed"
        return 0
    else
        echo "[ERROR] Snort IPS rule validation failed"
        echo "Check:"
        echo "sudo tail -100 $SNORT_VALIDATE_LOG"
        return 1
    fi
}

start_snort_ips() {
    echo
    echo "[STEP 3] Starting Snort IPS inline NFQUEUE"
    echo "[+] Active IPS rules: $IPS_RULE_FILE"
    echo "[+] Log file: $SNORT_STDOUT"

    mkdir -p "$SNORT_LOG_DIR"
    : > "$SNORT_STDOUT"

    # Kill old Snort IPS process if any
    pkill -f "snort.*--daq nfq.*queue=0" 2>/dev/null || true
    sleep 1

    stdbuf -oL -eL "$SNORT_BIN" \
    --daq-dir "$DAQ_DIR" \
    -c "$SNORT_CONF" \
    -R "$IPS_RULE_FILE" \
    -Q --daq nfq --daq-var queue=0 \
    -A alert_fast \
    -l "$SNORT_LOG_DIR" \
    > "$SNORT_STDOUT" 2>&1 &

    SNORT_PID=$!

    sleep 2

    if ! kill -0 "$SNORT_PID" 2>/dev/null; then
        echo "[ERROR] Snort IPS failed to start."
        echo "Check:"
        echo "sudo tail -100 $SNORT_STDOUT"
        exit 1
    fi

    echo "[OK] Snort IPS started. PID=$SNORT_PID"
}

restart_snort_ips() {
    echo
    echo "---------------------------------------------------------"
    echo "[ACTION] active_ips.rules changed. Reloading Snort IPS..."
    echo "---------------------------------------------------------"

    if ! validate_rules; then
        echo "[SKIP] Snort IPS was not restarted because rules are invalid."
        return
    fi

    if [ -n "$SNORT_PID" ]; then
        kill "$SNORT_PID" 2>/dev/null || true
        sleep 1
    fi

    start_snort_ips
}

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo:"
    echo "sudo bash ~/c2-defense-lab/automation/start_snort_ips.sh"
    exit 1
fi

if [ ! -x "$SNORT_BIN" ]; then
    echo "[ERROR] Snort binary not found or not executable: $SNORT_BIN"
    exit 1
fi

if [ ! -f "$SNORT_CONF" ]; then
    echo "[ERROR] Snort config not found: $SNORT_CONF"
    exit 1
fi

if [ ! -f "$IPS_RULE_FILE" ]; then
    echo "[ERROR] IPS rule file not found: $IPS_RULE_FILE"
    echo "Run:"
    echo "sudo /usr/local/bin/rebuild_snort_rule_sets.sh"
    exit 1
fi

echo "========================================================="
echo "TERMINAL 2 - SNORT IPS WATCHER"
echo "SYNCHRONIZED VERSION"
echo "========================================================="
echo "[+] Snort binary: $SNORT_BIN"
echo "[+] Snort config: $SNORT_CONF"
echo "[+] Active IPS rules: $IPS_RULE_FILE"
echo "[+] Gateway script: $GATEWAY_SCRIPT"
echo "========================================================="

apply_gateway_ips

if ! validate_rules; then
    exit 1
fi

start_snort_ips

LAST_HASH="$(calc_hash)"

echo
echo "========================================================="
echo "[OK] IPS TERMINAL READY"
echo "========================================================="
echo "Mode       : IPS inline"
echo "NFQUEUE    : ON"
echo "Action     : detect + block/drop"
echo "Rule file  : $IPS_RULE_FILE"
echo "Live log   : $SNORT_STDOUT"
echo "========================================================="
echo

if [ -x /usr/local/bin/snort_pretty_tail ]; then
    /usr/local/bin/snort_pretty_tail "$SNORT_STDOUT" &
    TAIL_PID=$!
else
    echo "[WARN] /usr/local/bin/snort_pretty_tail not found. Using raw tail."
    tail -f "$SNORT_STDOUT" &
    TAIL_PID=$!
fi

while true; do
    NEW_HASH="$(calc_hash)"

    if [ "$NEW_HASH" != "$LAST_HASH" ]; then
        LAST_HASH="$NEW_HASH"
        restart_snort_ips
    fi

    if ! kill -0 "$SNORT_PID" 2>/dev/null; then
        echo "[WARN] Snort IPS stopped. Restarting..."
        restart_snort_ips
    fi

    if ! check_nfqueue; then
        echo "[WARN] NFQUEUE disappeared. Re-applying gateway IPS mode..."
        apply_gateway_ips
    fi

    sleep 1
done
