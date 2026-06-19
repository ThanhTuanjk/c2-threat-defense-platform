# Troubleshooting

## Snort Does Not Block

Check:

```bash
sudo iptables -L FORWARD -v -n --line-numbers | grep NFQUEUE
pgrep -af 'snort.*--daq nfq'
sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/active_ips.rules -T
```

Common causes:

- Gateway is in observe mode.
- Snort IPS is not running.
- Rule action is `alert` instead of `block`.
- Traffic is not traversing NFQUEUE.

## Zeek Does Not Show HTTP for a Blocked Flow

If Snort drops the TCP SYN, there is no HTTP request yet. Look for `LabPreL7::Suspicious_Connection_Attempt` in `notice.log` and correlate with Snort's block event.

## Zeek Reports Checksum Offloading

The start script uses `zeek -C -i <interface>` to avoid VMware checksum-offloading confusion.

## Logs Are Too Noisy

Windows telemetry, reverse DNS, Tailscale, and Wazuh traffic can add noise. Use allowlists carefully and document what was filtered.

## Wazuh Active Response Does Not Fire

Confirm Sysmon Event ID 1, 3, and 22 are present. Without endpoint events, Wazuh cannot reliably map a network IOC to a process.

