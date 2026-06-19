#!/bin/bash

# =========================================================
# TERMINAL 1 - ZEEK + PYTHON AUTO RULE ENGINE
# NFQUEUE-INDEPENDENT VERSION
#
# Purpose:
# - Zeek always runs on ens33
# - Python engine can run and generate rules
# - NFQUEUE is optional:
#     + NFQUEUE ON  = IPS mode active
#     + NFQUEUE OFF = IDS / monitoring mode, no blocking
# =========================================================

LAB_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo ~$LAB_USER)"

LAB_DIR="${USER_HOME}/c2-defense-lab"
ZEEK_DIR="${LAB_DIR}/zeek/day6_auto_response"
LAN_IF="ens33"

PY_SCRIPT="${LAB_DIR}/automation/python_engine.py"

if [ ! -f "$PY_SCRIPT" ]; then
    PY_SCRIPT="${LAB_DIR}/automation/zeek_auto_rule_engine_v2.py"
fi

REBUILD_SCRIPT="/usr/local/bin/rebuild_snort_rule_sets.sh"
PRETTY_VIEW="/usr/local/bin/c2_pretty_tail"

ZEEK_PID=""
PY_PID=""
VIEW_PID=""

# Hold an exclusive lock on this script while the lab is running. This keeps
# two terminals from starting separate Zeek/Python stacks on the same NIC.
exec 9<"$0"
if ! flock -n 9; then
    echo "[ERROR] Another Zeek + Python lab terminal is already running."
    echo "[INFO] Stop the existing terminal with Ctrl+C before starting a new one."
    exit 1
fi

cleanup() {
    echo
    echo "[+] Stopping Zeek + Python terminal..."

    if [ -n "$ZEEK_PID" ]; then
        kill "$ZEEK_PID" 2>/dev/null || true
    fi

    if [ -n "$PY_PID" ]; then
        kill "$PY_PID" 2>/dev/null || true
    fi

    if [ -n "$VIEW_PID" ]; then
        kill "$VIEW_PID" 2>/dev/null || true
    fi

    pkill -P $$ 2>/dev/null || true

    echo "[+] Stopped."
    exit 0
}

trap cleanup INT TERM

check_nfqueue() {
    iptables -L FORWARD -v -n --line-numbers 2>/dev/null | grep -q "NFQUEUE"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo:"
    echo "sudo bash ~/c2-defense-lab/automation/start_zeek_python.sh"
    exit 1
fi

mkdir -p "$ZEEK_DIR"

echo "========================================================="
echo "TERMINAL 1 - ZEEK + PYTHON AUTO RULE ENGINE"
echo "NFQUEUE-INDEPENDENT VERSION"
echo "========================================================="
echo "[+] Lab dir       : $LAB_DIR"
echo "[+] Zeek dir      : $ZEEK_DIR"
echo "[+] LAN interface : $LAN_IF"
echo "[+] Python script : $PY_SCRIPT"
echo "========================================================="

echo
echo "[STEP 1] Checking NFQUEUE status"

if check_nfqueue; then
    echo "[OK] NFQUEUE found."
    echo "[MODE] IPS mode is active. Snort IPS can block traffic."
else
    echo "[WARN] NFQUEUE not found."
    echo "[MODE] IDS / Monitoring mode."
    echo "[INFO] Zeek will still run normally."
    echo "[INFO] Python can still analyze Zeek logs and generate rules."
    echo "[INFO] No packet blocking happens until Snort IPS is started."
fi

echo
echo "[STEP 2] Rebuilding Snort rule sets if script exists"

if [ -x "$REBUILD_SCRIPT" ]; then
    "$REBUILD_SCRIPT" || true
else
    echo "[WARN] Rebuild script not found: $REBUILD_SCRIPT"
fi

echo
echo "[STEP 3] Cleaning old Zeek logs"

mapfile -t EXISTING_ZEEK_PIDS < <(
    pgrep -f "^/opt/zeek/bin/zeek( .*)? -i ${LAN_IF}([[:space:]]|$)" 2>/dev/null || true
)

if [ "${#EXISTING_ZEEK_PIDS[@]}" -gt 0 ]; then
    echo "[ERROR] Zeek is already capturing on ${LAN_IF}: PID(s) ${EXISTING_ZEEK_PIDS[*]}"
    echo "[INFO] Existing logs were NOT deleted. Stop the old Zeek process, then run this script again."
    exit 1
fi

rm -f "$ZEEK_DIR"/*.log 2>/dev/null || true

echo
echo "[STEP 4] Starting Zeek on $LAN_IF"

cd "$ZEEK_DIR" || exit 1

# VMware checksum offloading exposes pre-checksum packets to packet capture.
# -C prevents Zeek from discarding those otherwise valid forwarded packets.
/opt/zeek/bin/zeek -C -i "$LAN_IF" local &
ZEEK_PID=$!

sleep 2

if ! kill -0 "$ZEEK_PID" 2>/dev/null; then
    echo "[ERROR] Zeek failed to start."
    exit 1
fi

echo "[OK] Zeek started. PID=$ZEEK_PID"

echo
echo "[STEP 5] Starting Python auto-rule engine"

if [ -f "$PY_SCRIPT" ]; then
    python3 "$PY_SCRIPT" "$ZEEK_DIR" &
    PY_PID=$!
    sleep 1

    if kill -0 "$PY_PID" 2>/dev/null; then
        echo "[OK] Python engine started. PID=$PY_PID"
    else
        echo "[WARN] Python engine stopped or failed to start."
        echo "[INFO] Zeek still continues running."
    fi
else
    echo "[WARN] Python script not found."
    echo "[INFO] Running Zeek only."
fi

echo
echo "[STEP 6] Starting Zeek pretty view"

if [ -x "$PRETTY_VIEW" ]; then
    "$PRETTY_VIEW" "$ZEEK_DIR" &
    VIEW_PID=$!
    echo "[OK] Zeek pretty view started. PID=$VIEW_PID"
else
    echo "[WARN] Pretty view not found: $PRETTY_VIEW"
    echo "[INFO] Raw Zeek logs are in: $ZEEK_DIR"
fi

echo
echo "========================================================="
echo "[OK] ZEEK TERMINAL READY"
echo "========================================================="
echo "Zeek status        : RUNNING"
echo "Python status      : CHECK ABOVE"
if check_nfqueue; then
    echo "Current mode       : IPS / Auto-response ready"
else
    echo "Current mode       : IDS / Monitoring only"
fi
echo
echo "Meaning:"
echo "  - Zeek logs HTTP/DNS/TLS/conn traffic"
echo "  - Python can generate auto rules from Zeek logs"
echo "  - If Snort IPS is not running, no traffic is blocked"
echo "  - If Snort IPS is running, generated rules can be used for blocking"
echo
echo "Ctrl+C to stop this terminal"
echo "========================================================="

while true; do
    if ! kill -0 "$ZEEK_PID" 2>/dev/null; then
        echo "[ERROR] Zeek stopped."
        exit 1
    fi

    if [ -n "$PY_PID" ] && ! kill -0 "$PY_PID" 2>/dev/null; then
        echo "[WARN] Python engine stopped. Zeek is still running."
        PY_PID=""
    fi

    sleep 1
done
