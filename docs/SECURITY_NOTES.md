# Security Notes

- Keep malware testing inside isolated VMs.
- Do not connect the Windows malware-test VM directly to NAT/Bridged Internet.
- Keep Ubuntu FORWARD policy as DROP.
- Allow Wazuh ports only for the specific manager IP.
- Do not publish real packet captures, Wazuh keys, endpoint usernames, public IPs, or runtime logs.
- Prefer fake domains and sanitized examples in screenshots and documentation.

