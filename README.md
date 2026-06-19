# C2 Threat Defense Platform

A safe, reproducible C2/malware defense platform for a small-enterprise network model. The platform forces a Windows endpoint through an Ubuntu gateway, redirects unsafe Internet-like traffic to INetSim/Fake C2, detects activity with Snort IDS and Zeek, blocks selected flows with Snort IPS through NFQUEUE, and uses a Python engine to generate Snort rules from Zeek telemetry.

> This repository is a sanitized defensive platform framework. It does not include private logs, packet captures, malware samples, raw runtime state, or the original DOCX report.

## What This Platform Demonstrates

- Ubuntu as gateway, firewall, router, NAT/DNAT point, Snort IDS/IPS host, Zeek sensor, and Python automation runner.
- Windows client traffic forced through the gateway, with no direct Internet path.
- Kali/INetSim as a safe Fake Internet/Fake C2 target.
- Wazuh/Sysmon endpoint visibility as a complementary layer.
- IDS versus IPS behavior:
  - IDS alerts but does not block.
  - IPS blocks only when traffic passes NFQUEUE and the matching rule action is `block`/`drop`.
- Zeek visibility for HTTP/DNS/TLS/connection metadata, including pre-L7 notices for blocked high-port C2 attempts.
- Python auto-rule generation from Zeek logs for "observe first, block next" workflows.

## System Roles

| Role | Default IP | Purpose |
| --- | --- | --- |
| Windows Client | `192.168.100.20/24` | Endpoint that generates benign tests and controlled malware/C2 behavior |
| Ubuntu Gateway | `192.168.100.10`, `10.10.10.10` | Firewall, router, Snort, Zeek, Python auto-rule engine |
| Kali/INetSim | `10.10.10.20` | Fake Internet/Fake C2 DNS/HTTP service |
| Wazuh Server | set in `.env` | Endpoint log collection and future active response |

## Quick Start

```bash
git clone https://github.com/ThanhTuanjk/c2-threat-defense-platform.git
cd c2-threat-defense-platform
cp .env.example .env
# Edit .env to match your VM interfaces and IP addresses.
sudo bash install/check_prereqs.sh
sudo bash install/deploy_ubuntu_gateway.sh
```

Start the main platform terminals on Ubuntu:

```bash
sudo bash ~/c2-defense-lab/automation/start_zeek_python.sh
sudo bash ~/c2-defense-lab/automation/start_snort_ips.sh
```

IDS-only demo:

```bash
sudo bash ~/c2-defense-lab/automation/start_snort_ids.sh
```

Windows test examples:

```powershell
nslookup google.com 10.10.10.20
curl.exe -v --max-time 8 -H "Host: c2-test.lab" -A "Go-http-client/1.1" "http://10.10.10.20/beacon.php?test=ids"
Test-NetConnection 10.10.10.20 -Port 56003
```

## Documentation Map

- [Architecture](docs/ARCHITECTURE.md)
- [Network topology](docs/NETWORK_TOPOLOGY.md)
- [Ubuntu gateway setup](docs/SETUP_UBUNTU_GATEWAY.md)
- [Windows client setup](docs/SETUP_WINDOWS_CLIENT.md)
- [Kali INetSim setup](docs/SETUP_KALI_INETSIM.md)
- [Wazuh server setup](docs/SETUP_WAZUH_SERVER.md)
- [IDS runbook](docs/RUNBOOK_IDS.md)
- [IPS runbook](docs/RUNBOOK_IPS.md)
- [Test plan](docs/TEST_PLAN.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Current project status](docs/PROJECT_STATUS.md)

## Repository Layout

```text
automation/     Start scripts and Python auto-rule engine
config/         Snort and Zeek configuration used by the platform
docs/           Architecture, setup, runbooks, test plan
examples/       Safe test commands and expected evidence
install/        Deployment helpers for the Ubuntu gateway
rules/          Local Snort IDS/IPS rules and auto-rule examples
scripts/        Gateway firewall mode scripts
tools/          Pretty log viewers and Snort rule rebuild tool
```

## Safety Boundary

This platform is designed for controlled defensive education and enterprise-style validation. Do not run real malware outside an isolated VM network. Do not publish runtime logs or packet captures without sanitizing them first.

