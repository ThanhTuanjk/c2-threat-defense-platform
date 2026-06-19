# Safe Test Commands

Windows PowerShell:

```powershell
nslookup google.com 10.10.10.20
curl.exe -v --max-time 8 -H "Host: c2-test.lab" -A "Go-http-client/1.1" "http://10.10.10.20/beacon.php?test=ids"
curl.exe -v --max-time 8 -H "Host: c2-test.lab" -A "Mozilla/5.0" "http://10.10.10.20/"
Test-NetConnection 10.10.10.20 -Port 56003
```

Ubuntu checks:

```bash
sudo tail -F /var/log/snort/snort_ips_stdout.log
sudo tail -F /var/log/snort_ids/snort_ids_stdout.log
cd ~/c2-defense-lab/zeek/day6_auto_response
/opt/zeek/bin/zeek-cut -d ts id.orig_h id.resp_h id.resp_p proto service conn_state < conn.log | tail
```

