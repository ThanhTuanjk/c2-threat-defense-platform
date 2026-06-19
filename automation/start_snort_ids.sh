#!/bin/bash

# =========================================================
# TERMINAL IDS
# SNORT IDS - DETECTION ONLY MODE
#
# Purpose:
# 1. Preserve Gateway IPS/NFQUEUE mode if IPS is already running
# 2. Apply Gateway OBSERVE mode only for IDS-only runs
# 3. Validate active_ids.rules
# 4. Start Snort IDS on ens33
# 5. Show clear IDS alert table
#
# IDS meaning:
# - Detect only
# - Alert only
# - Never disables a running Snort IPS/NFQUEUE session
# =========================================================

SNORT_BIN="$(command -v snort)"
DAQ_DIR="/usr/local/lib/daq"
SNORT_CONF="/usr/local/etc/snort/snort.lua"
IDS_RULE_FILE="/usr/local/etc/rules/active_ids.rules"

LAN_IF="ens33"

IDS_LOG_DIR="/var/log/snort_ids"
IDS_STDOUT="${IDS_LOG_DIR}/snort_ids_stdout.log"
IDS_VALIDATE_LOG="${IDS_LOG_DIR}/snort_ids_validate.log"
IDS_STREAM_PIPE="/tmp/snort_ids_stream.fifo"

LAB_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo ~$LAB_USER)"
GATEWAY_SCRIPT="${USER_HOME}/c2-defense-lab/scripts/gateway_ids_observe.sh"
GATEWAY_LOG="/tmp/lab_gateway_ids_start.log"

SNORT_PID=""
TAIL_PID=""
LAST_HASH=""
IDS_FIREWALL_MODE="unknown"

cleanup() {
    echo
    echo "[+] Stopping Snort IDS..."

    if [ -n "$SNORT_PID" ]; then
        kill "$SNORT_PID" 2>/dev/null || true
    fi

    if [ -n "$TAIL_PID" ]; then
        kill "$TAIL_PID" 2>/dev/null || true
    fi

    pkill -P $$ 2>/dev/null || true
    rm -f "$IDS_STREAM_PIPE" 2>/dev/null || true

    echo "[+] Stopped Snort IDS."
    exit 0
}

trap cleanup INT TERM

calc_hash() {
    if [ -f "$IDS_RULE_FILE" ]; then
        sha256sum "$IDS_RULE_FILE" | awk '{print $1}'
    else
        echo "missing"
    fi
}

has_nfqueue() {
    iptables -L FORWARD -v -n --line-numbers | grep -q "NFQUEUE"
}

ips_inline_running() {
    pgrep -f "snort.*--daq nfq.*queue=0" >/dev/null 2>&1
}

show_forward_rules() {
    iptables -L FORWARD -v -n --line-numbers
}

apply_gateway_observe() {
    echo
    echo "[STEP 1] Checking gateway mode for IDS"

    if has_nfqueue; then
        if ips_inline_running; then
            IDS_FIREWALL_MODE="coexist_ips"
            echo "[OK] NFQUEUE is active and Snort IPS is running."
            echo "[OK] Keeping IPS inline mode. IDS will listen passively and will NOT change firewall rules."
            return 0
        fi

        echo "[WARN] NFQUEUE exists but Snort IPS process was not found."
        echo "[INFO] Treating this as stale IPS state and switching to IDS observe mode."
    fi

    echo "[INFO] Applying Gateway OBSERVE mode for IDS-only run"

    if [ ! -f "$GATEWAY_SCRIPT" ]; then
        echo "[ERROR] Gateway script not found:"
        echo "        $GATEWAY_SCRIPT"
        exit 1
    fi

    bash "$GATEWAY_SCRIPT" observe > "$GATEWAY_LOG" 2>&1

    if has_nfqueue; then
        echo "[ERROR] NFQUEUE still exists after applying observe mode."
        echo "Current FORWARD rules:"
        show_forward_rules
        echo
        echo "Check gateway log:"
        echo "sudo cat $GATEWAY_LOG"
        exit 1
    else
        IDS_FIREWALL_MODE="observe"
        echo "[OK] Gateway observe mode active."
        echo "[OK] No NFQUEUE found. IDS-only traffic will NOT be intercepted by IPS."
    fi
}

validate_rules() {
    echo
    echo "[STEP 2] Validating Snort IDS rules"
    echo "[+] Rule file: $IDS_RULE_FILE"

    "$SNORT_BIN" -c "$SNORT_CONF" -R "$IDS_RULE_FILE" -T > "$IDS_VALIDATE_LOG" 2>&1

    if [ $? -eq 0 ]; then
        echo "[OK] Snort IDS rule validation passed"
        return 0
    else
        echo "[ERROR] Snort IDS rule validation failed"
        echo "Check:"
        echo "sudo tail -100 $IDS_VALIDATE_LOG"
        return 1
    fi
}

start_snort_ids() {
    echo
    echo "[STEP 3] Starting Snort IDS passive listener"
    echo "[+] Interface: $LAN_IF"
    echo "[+] IDS rule file: $IDS_RULE_FILE"

    mkdir -p "$IDS_LOG_DIR"
    : > "$IDS_STDOUT"

    rm -f "$IDS_STREAM_PIPE"
    mkfifo "$IDS_STREAM_PIPE"

    /usr/local/bin/snort_ids_tail - < "$IDS_STREAM_PIPE" &
    TAIL_PID=$!

    stdbuf -oL -eL "$SNORT_BIN" --daq-dir "$DAQ_DIR" \
    -c "$SNORT_CONF" \
    -R "$IDS_RULE_FILE" \
    -i "$LAN_IF" \
    -k none \
    -A alert_fast \
    -l "$IDS_LOG_DIR" \
    > >(stdbuf -oL -eL tee -a "$IDS_STDOUT" > "$IDS_STREAM_PIPE") 2>&1 &

    SNORT_PID=$!

    sleep 2

    if ! kill -0 "$SNORT_PID" 2>/dev/null; then
        echo "[ERROR] Snort IDS failed to start."
        echo "Check:"
        echo "sudo tail -100 $IDS_STDOUT"
        exit 1
    fi

    echo "[OK] Snort IDS started. PID=$SNORT_PID"
}

restart_snort_ids() {
    echo
    echo "---------------------------------------------------------"
    echo "[ACTION] active_ids.rules changed. Reloading Snort IDS..."
    echo "---------------------------------------------------------"

    if ! validate_rules; then
        echo "[SKIP] Snort IDS was not restarted because rules are invalid."
        return
    fi

    if [ -n "$SNORT_PID" ]; then
        kill "$SNORT_PID" 2>/dev/null || true
        sleep 2
    fi

    start_snort_ids
}

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo:"
    echo "sudo bash ~/c2-defense-lab/automation/start_snort_ids.sh"
    exit 1
fi

if [ -z "$SNORT_BIN" ]; then
    echo "[ERROR] snort command not found"
    exit 1
fi

if [ ! -f "$IDS_RULE_FILE" ]; then
    echo "[ERROR] IDS rule file not found:"
    echo "        $IDS_RULE_FILE"
    echo "Run:"
    echo "sudo /usr/local/bin/rebuild_snort_rule_sets.sh"
    exit 1
fi

mkdir -p "$IDS_LOG_DIR"

echo "========================================================="
echo "TERMINAL IDS - SNORT DETECTION ONLY"
echo "========================================================="
echo "[+] Mode: IDS"
echo "[+] Meaning: Alert only, no block"
echo "[+] Snort binary: $SNORT_BIN"
echo "[+] Snort config: $SNORT_CONF"
echo "[+] IDS rules: $IDS_RULE_FILE"
echo "[+] Interface: $LAN_IF"
echo "[+] Gateway script: $GATEWAY_SCRIPT"
echo

apply_gateway_observe

if ! validate_rules; then
    exit 1
fi

start_snort_ids

LAST_HASH="$(calc_hash)"

echo
echo "========================================================="
echo "[OK] IDS TERMINAL READY"
echo "========================================================="
if [ "$IDS_FIREWALL_MODE" = "coexist_ips" ]; then
    echo "Gateway mode: IPS inline preserved"
    echo "NFQUEUE: ON - kept for Snort IPS"
else
    echo "Gateway observe mode: OK"
    echo "NFQUEUE: OFF"
fi
echo "Snort IDS: OK"
echo
echo "IDS behavior:"
echo "  - Snort will detect and alert"
echo "  - Snort IDS will NOT block"
echo "  - If IPS is running, Snort IPS can still block through NFQUEUE"
echo "  - IDS will not re-apply observe mode over a running IPS"
echo
echo "Watching:"
echo "  $IDS_RULE_FILE"
echo
echo "Snort IDS event live:"
echo "  $IDS_STDOUT"
echo
echo "Ctrl+C to stop Snort IDS"
echo "========================================================="
echo

if [ -z "$TAIL_PID" ]; then
    /usr/local/bin/snort_ids_tail "$IDS_STDOUT" &
    TAIL_PID=$!
fi

while true; do
    NEW_HASH="$(calc_hash)"

    if [ "$NEW_HASH" != "$LAST_HASH" ]; then
        LAST_HASH="$NEW_HASH"
        restart_snort_ids
    fi

    if ! kill -0 "$SNORT_PID" 2>/dev/null; then
        echo "[WARN] Snort IDS process stopped. Restarting..."
        restart_snort_ids
    fi

    if has_nfqueue; then
        if ips_inline_running; then
            if [ "$IDS_FIREWALL_MODE" != "coexist_ips" ]; then
                IDS_FIREWALL_MODE="coexist_ips"
                echo "[INFO] NFQUEUE detected with Snort IPS running."
                echo "[INFO] Keeping IPS inline mode; IDS remains passive."
            fi
        else
            if [ "$IDS_FIREWALL_MODE" != "stale_nfqueue" ]; then
                IDS_FIREWALL_MODE="stale_nfqueue"
                echo "[WARN] NFQUEUE exists but Snort IPS process is not running."
                echo "[WARN] IDS will not remove it while running. Restart IDS or start IPS if traffic stalls."
            fi
        fi
    else
        if [ "$IDS_FIREWALL_MODE" = "coexist_ips" ] || [ "$IDS_FIREWALL_MODE" = "stale_nfqueue" ]; then
            IDS_FIREWALL_MODE="observe"
            echo "[WARN] NFQUEUE is no longer present. IDS is now observe-only."
        fi
    fi

    sleep 2
done
