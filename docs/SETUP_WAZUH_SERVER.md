# Setup: Wazuh Server

Wazuh is the endpoint visibility layer. Snort and Zeek see network behavior; Wazuh/Sysmon can identify process name, PID, command line, user, and hash if Sysmon is configured well.

## Network Exception

Set the Wazuh manager IP in `.env`:

```bash
WAZUH_SERVER_IP=10.10.20.20
WAZUH_PORTS=1514,1515
```

The Ubuntu firewall allows only Windows client traffic to these Wazuh ports and does not DNAT it to INetSim.

## Agent Checks

On Windows, verify the Wazuh Agent is enrolled and sending logs. On the Wazuh Server, verify the agent appears active.

## Active Response Status

Active Response kill-process logic is a future/experimental layer in this platform. Treat it as not production-ready until Sysmon Event ID 1/3/22 coverage is verified and the Wazuh rule reliably triggers on the intended test event.

