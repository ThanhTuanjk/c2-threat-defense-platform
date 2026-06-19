# Runbook: Snort IPS

IPS mode applies gateway rules, enables NFQUEUE, validates `active_ips.rules`, then starts Snort with DAQ NFQ.

```bash
sudo bash ~/c2-defense-lab/automation/start_snort_ips.sh
```

Expected terminal state:

- `Gateway IPS mode: OK`
- `NFQUEUE: OK`
- `Snort IPS: OK`

Test high-port C2 behavior:

```powershell
Test-NetConnection 10.10.10.20 -Port 56003
```

Expected evidence:

- Snort shows `BLOCK / DROP`.
- Zeek shows a pre-L7 suspicious connection notice.
- There is no completed HTTP record for a SYN blocked before Layer 7 exists.

