# Setup: Windows Client

Windows represents the internal endpoint that may run benign tests or controlled malware/C2 behavior.

## Network

Configure the Windows lab adapter:

```text
IP address: 192.168.100.20
Netmask:    255.255.255.0
Gateway:    192.168.100.10
DNS:        10.10.10.20 or 192.168.100.10 depending on your demo
```

Do not attach a separate NAT/bridged Internet adapter to the malware test VM unless you explicitly know why.

## Wazuh Agent and Sysmon

Recommended endpoint telemetry:

- Wazuh Agent connected to your Wazuh Server.
- Sysmon configured to capture process creation, network connections, and DNS events.
- PowerShell logging enabled if your tests include PowerShell behavior.

Important Sysmon event IDs:

| Event ID | Purpose |
| --- | --- |
| 1 | Process Create |
| 3 | Network Connection |
| 11 | File Create |
| 22 | DNS Query |

## Safe Test Commands

```powershell
nslookup google.com 10.10.10.20
curl.exe -v --max-time 8 -H "Host: c2-test.lab" -A "Go-http-client/1.1" "http://10.10.10.20/beacon.php?test=ids"
Test-NetConnection 10.10.10.20 -Port 56003
```

Expected result:

- Normal DNS/HTTP traffic appears in Zeek.
- IDS alerts but does not block.
- IPS blocks known C2/high-risk flows when NFQUEUE is active.

