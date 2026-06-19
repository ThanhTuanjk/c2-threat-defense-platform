# Setup: Ubuntu Gateway

Ubuntu is the central control point. It runs the firewall, Snort IDS/IPS, Zeek, the Python auto-rule engine, and the pretty log viewers.

## 1. Clone and Configure

```bash
git clone https://github.com/ThanhTuanjk/c2-threat-defense-platform.git
cd c2-threat-defense-platform
cp .env.example .env
nano .env
```

Set the interface names and IPs to match your VM.

## 2. Check Prerequisites

```bash
sudo bash install/check_prereqs.sh
```

The helper checks for Snort, Zeek, Python, iptables, and required paths. It does not compile Snort or Zeek for you.

## 3. Deploy Platform Files

```bash
sudo bash install/deploy_ubuntu_gateway.sh
```

This installs:

- firewall scripts into `~/c2-defense-lab/scripts`
- automation scripts into `~/c2-defense-lab/automation`
- viewer tools into `/usr/local/bin`
- rules into `/usr/local/etc/rules`
- Zeek policy into `/opt/zeek/share/zeek/site/local.zeek`
- Snort config into `/usr/local/etc/snort/snort.lua`

## 4. Start Zeek and Python

```bash
sudo bash ~/c2-defense-lab/automation/start_zeek_python.sh
```

## 5. Start IPS

```bash
sudo bash ~/c2-defense-lab/automation/start_snort_ips.sh
```

## 6. Start IDS Only

```bash
sudo bash ~/c2-defense-lab/automation/start_snort_ids.sh
```

IDS mode detects and alerts only. IPS mode blocks when NFQUEUE and rule action match.

