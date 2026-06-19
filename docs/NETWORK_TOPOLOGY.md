# Network Topology

Default addressing used by the lab:

| Role | Interface | IP | Notes |
| --- | --- | --- | --- |
| Ubuntu Gateway LAN | `ens33` | `192.168.100.10/24` | Windows default gateway |
| Ubuntu Fake Outside | `ens37` | `10.10.10.10/24` | Path to INetSim |
| Ubuntu Wazuh/External Path | `ens38` | lab-specific | Optional Wazuh route |
| Windows Client | adapter on internal LAN | `192.168.100.20/24` | Gateway `192.168.100.10` |
| Kali/INetSim | fake outside network | `10.10.10.20/24` | DNS/HTTP fake services |
| Wazuh Server | user-defined | `.env: WAZUH_SERVER_IP` | Allowed TCP `1514,1515` |

## Traffic Policy

- Windows normal TCP/UDP traffic is DNATed to INetSim.
- Wazuh agent traffic is explicitly exempted from DNAT.
- Forward policy is DROP.
- Non-INetSim/non-Wazuh traffic from Windows is logged with `LAB-LEAK-DROP` and dropped.

## Why Zeek May Show Original IPs

Zeek listens on the LAN side and can observe the destination before NAT/DNAT rewriting is fully interpreted by a reader. Seeing an original public destination in Zeek does not automatically mean Internet leakage. Verify leakage with firewall counters and packet capture on the real external interface.

