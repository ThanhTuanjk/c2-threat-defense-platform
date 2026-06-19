#!/bin/bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

LAB_USER="${SUDO_USER:-ubuntu}"
USER_HOME="$(eval echo "~${LAB_USER}")"
LAB_DIR="${USER_HOME}/c2-defense-lab"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

install -d -o "$LAB_USER" -g "$LAB_USER" "$LAB_DIR/scripts" "$LAB_DIR/automation" "$LAB_DIR/zeek/day6_auto_response"
install -d /usr/local/etc/rules /usr/local/etc/snort /usr/local/bin

install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/scripts/config_firewall" "$LAB_DIR/scripts/config_firewall"
install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/scripts/lab_gateway_rules.sh" "$LAB_DIR/scripts/lab_gateway_rules.sh"
install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/scripts/gateway_ids_observe.sh" "$LAB_DIR/scripts/gateway_ids_observe.sh"
install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/scripts/gateway_ips_inline.sh" "$LAB_DIR/scripts/gateway_ips_inline.sh"

install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/automation/start_snort_ids.sh" "$LAB_DIR/automation/start_snort_ids.sh"
install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/automation/start_snort_ips.sh" "$LAB_DIR/automation/start_snort_ips.sh"
install -o "$LAB_USER" -g "$LAB_USER" -m 775 "$ROOT_DIR/automation/start_zeek_python.sh" "$LAB_DIR/automation/start_zeek_python.sh"
install -o "$LAB_USER" -g "$LAB_USER" -m 755 "$ROOT_DIR/automation/python_engine.py" "$LAB_DIR/automation/python_engine.py"

install -o root -g root -m 755 "$ROOT_DIR/tools/rebuild_snort_rule_sets.sh" /usr/local/bin/rebuild_snort_rule_sets.sh
install -o root -g root -m 755 "$ROOT_DIR/tools/c2_pretty_tail" /usr/local/bin/c2_pretty_tail
install -o root -g root -m 755 "$ROOT_DIR/tools/snort_pretty_tail" /usr/local/bin/snort_pretty_tail
install -o root -g root -m 755 "$ROOT_DIR/tools/snort_ids_tail" /usr/local/bin/snort_ids_tail

install -o root -g root -m 644 "$ROOT_DIR/rules/local_ips.rules" /usr/local/etc/rules/local_ips.rules
install -o root -g root -m 755 "$ROOT_DIR/rules/local_ids.rules" /usr/local/etc/rules/local_ids.rules
if [ ! -f /usr/local/etc/rules/local_auto.rules ]; then
    install -o root -g root -m 644 "$ROOT_DIR/rules/local_auto.rules.example" /usr/local/etc/rules/local_auto.rules
fi
if [ ! -f /usr/local/etc/rules/local_auto_ids.rules ]; then
    install -o root -g root -m 644 "$ROOT_DIR/rules/local_auto_ids.rules.example" /usr/local/etc/rules/local_auto_ids.rules
fi

install -o root -g root -m 644 "$ROOT_DIR/config/snort/snort.lua" /usr/local/etc/snort/snort.lua
install -o root -g zeek -m 664 "$ROOT_DIR/config/zeek/local.zeek" /opt/zeek/share/zeek/site/local.zeek

if [ -f "$ROOT_DIR/.env" ]; then
    install -o "$LAB_USER" -g "$LAB_USER" -m 600 "$ROOT_DIR/.env" "$LAB_DIR/.env"
fi

/usr/local/bin/rebuild_snort_rule_sets.sh

echo "[OK] Ubuntu gateway platform files deployed to $LAB_DIR"
echo "[NEXT] sudo bash $LAB_DIR/automation/start_zeek_python.sh"
echo "[NEXT] sudo bash $LAB_DIR/automation/start_snort_ips.sh"

