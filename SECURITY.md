# Security Policy

This repository is a defensive malware/C2 lab framework. It intentionally contains detection logic, Snort rules, and test commands, but it must not contain malware samples, credentials, private packet captures, or private runtime logs.

## Do Not Publish

- Real malware binaries or droppers.
- Private `.pcap`/`.pcapng` captures.
- `/var/log/*` runtime logs.
- `/var/lib/c2_auto_response/*` state databases.
- Wazuh enrollment keys, API tokens, SSH keys, passwords, or personal IPs.
- Raw IOC URL feeds unless they are defanged and licensed for redistribution.

## Safe Reporting

If you find a safety issue in this lab, open a private advisory or contact the maintainer before publishing exploit details.

