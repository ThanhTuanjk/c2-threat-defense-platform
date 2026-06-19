# Setup: Kali / INetSim

Kali or another Linux VM can host INetSim as the Fake Internet/Fake C2 target.

## Default Role

```text
IP address: 10.10.10.20/24
Gateway:    10.10.10.10
Services:   DNS, HTTP, optional HTTPS/SMTP/FTP depending on INetSim config
```

## Install and Start

Package names vary by distro. On Kali/Debian-style systems:

```bash
sudo apt update
sudo apt install -y inetsim
sudo systemctl stop inetsim 2>/dev/null || true
sudo inetsim
```

Check that DNS and HTTP are listening:

```bash
sudo ss -lntup | grep -E ':53|:80|:443'
```

## Validation

From Windows:

```powershell
nslookup google.com 10.10.10.20
curl.exe -v http://10.10.10.20/
```

INetSim should answer instead of allowing the client to contact the real Internet.

