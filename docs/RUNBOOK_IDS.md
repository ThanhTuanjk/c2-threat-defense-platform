# Runbook: Snort IDS

IDS mode is detection-only. It should not change an already-running IPS/NFQUEUE session.

```bash
sudo bash ~/c2-defense-lab/automation/start_snort_ids.sh
```

Expected terminal state:

- `Snort IDS: OK`
- `NFQUEUE: OFF` for IDS-only mode, or `NFQUEUE: ON - kept for Snort IPS` when IPS is already running.
- Alerts are displayed in the IDS viewer.

Test from Windows:

```powershell
curl.exe -v --max-time 8 -H "Host: c2-test.lab" -A "Go-http-client/1.1" "http://10.10.10.20/beacon.php?test=ids"
```

IDS should alert, but the request may still complete if no IPS is running.

