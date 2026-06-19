# Test Plan

## Baseline

On Ubuntu:

```bash
ip -br addr
sudo iptables -L FORWARD -v -n --line-numbers
sudo iptables -t nat -L PREROUTING -v -n --line-numbers
sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/active_ips.rules -T
/opt/zeek/bin/zeek -b /opt/zeek/share/zeek/site/local.zeek
```

## DNS

```powershell
nslookup google.com 10.10.10.20
```

Expected: Zeek DNS log shows the query. Snort observe rules may show DNS visibility depending on mode.

## HTTP C2 Pattern

```powershell
curl.exe -v --max-time 8 -H "Host: c2-test.lab" -A "Go-http-client/1.1" "http://10.10.10.20/beacon.php?test=ids"
```

Expected: Snort IDS alerts. IPS blocks if the matching block rule and NFQUEUE are active.

## Pre-L7 High-Port C2

```powershell
Test-NetConnection 10.10.10.20 -Port 56003
```

Expected:

- Snort IPS: block/drop for high-port C2 rule.
- Zeek: `LabPreL7::Suspicious_Connection_Attempt`.

## No Internet Leak

Confirm unexpected Windows traffic is DNATed to INetSim or dropped/logged by Ubuntu. Use firewall counters and packet capture on the real external path only in a controlled lab.

