# Architecture

The lab uses a four-role model:

```text
Windows Client
    |
    | 192.168.100.0/24 internal LAN
    v
Ubuntu Gateway
    |-- iptables firewall/NAT/DNAT
    |-- Snort IDS/IPS
    |-- Zeek network telemetry
    |-- Python auto-rule engine
    |
    | 10.10.10.0/24 fake outside network
    v
Kali/INetSim Fake Internet / Fake C2

Windows Wazuh Agent -> Ubuntu Gateway exception -> Wazuh Server
```

## Control Points

- `iptables` owns traffic steering and lab isolation.
- Snort IDS listens passively and alerts only.
- Snort IPS runs inline with NFQUEUE and can block/drop.
- Zeek records protocol and connection context.
- Python reads Zeek logs and writes auto-generated Snort rules.
- INetSim safely answers DNS/HTTP instead of letting malware reach the real Internet.
- Wazuh/Sysmon adds endpoint context such as process, command line, DNS query, and network events.

## IDS vs IPS

IDS evidence proves detection. IPS evidence proves prevention. A valid IPS block requires:

1. The packet enters the Ubuntu FORWARD path.
2. The matching flow is sent to NFQUEUE.
3. Snort IPS is running with DAQ NFQ.
4. The loaded rule action is `block` or `drop`.

## Zeek and Pre-L7 Blocks

When Snort drops a TCP SYN before the TCP session is established, Zeek cannot produce an HTTP record because no HTTP exists yet. The lab Zeek policy adds a `LabPreL7::Suspicious_Connection_Attempt` notice for selected high-risk C2 ports. That notice proves Zeek observed the real ingress attempt on `ens33`; Snort remains authoritative for the drop verdict.

