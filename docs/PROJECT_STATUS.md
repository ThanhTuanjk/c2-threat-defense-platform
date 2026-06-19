# Project Status

Verified during repository audit:

- Ubuntu Gateway scripts exist and are active source for firewall modes.
- Snort IDS and IPS rule files validate successfully with zero warnings.
- Zeek local policy validates successfully.
- Python auto-rule engine writes to `local_auto.rules`, rebuilds active rule sets, and tracks SID state under `/var/lib/c2_auto_response`.
- Zeek pre-L7 notice logic is used to represent TCP attempts blocked before HTTP exists.

Known limitations:

- Wazuh Active Response is documented as experimental until Sysmon/Wazuh trigger coverage is verified end to end.
- Raw IOC URL/IP/domain feeds are not included in this repository because they may contain live malicious infrastructure and redistribution concerns.
- Lab IPs are defaults. Edit `.env`, rules, and Zeek constants if your topology differs.

