#!/bin/bash
set -u

missing=0

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[MISSING] $1"
        missing=1
    else
        echo "[OK] $1"
    fi
}

need_file() {
    if [ ! -e "$1" ]; then
        echo "[MISSING] $1"
        missing=1
    else
        echo "[OK] $1"
    fi
}

need_cmd iptables
need_cmd python3
need_cmd awk
need_cmd grep
need_cmd sed
need_cmd tee
need_file /usr/local/bin/snort
need_file /opt/zeek/bin/zeek
need_file /usr/local/lib/daq

if [ "$missing" -ne 0 ]; then
    echo
    echo "[ERROR] Missing prerequisites. Install/build Snort 3, DAQ, and Zeek before deploying."
    exit 1
fi

echo
echo "[OK] Prerequisite check passed."

