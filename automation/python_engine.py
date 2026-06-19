#!/usr/bin/env python3
import os
import re
import json
import time
import math
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

LAN_CLIENT = os.getenv("LAN_CLIENT", "192.168.100.20")
HOME_NET = os.getenv("HOME_NET", "192.168.100.0/24")

RULE_DIR = Path("/usr/local/etc/rules")
BASE_RULE_FILE = RULE_DIR / "local_ips.rules"
AUTO_RULE_FILE = RULE_DIR / "local_auto.rules"
ACTIVE_RULE_FILE = RULE_DIR / "active_ips.rules"

IOC_DOMAIN_FILE = RULE_DIR / "ioc_domains.txt"
IOC_IP_FILE = RULE_DIR / "ioc_ips.txt"

STATE_DIR = Path("/var/lib/c2_auto_response")
SID_DB_FILE = STATE_DIR / "sid_db_v2.json"

RESPONSE_LOG = Path("/var/log/c2_auto_response_v2.log")
OBSERVE_LOG = Path("/var/log/c2_behavior_observe.log")
TLS_EVIDENCE_LOG = Path("/var/log/c2_tls_sni_evidence.log")

START_SID = 3100000
RULE_ACTION = os.getenv("RULE_ACTION", "block")

BAD_URI_KEYWORDS = [
    "/gate", "/beacon", "/checkin", "/callback", "/connect",
    "/panel", "/task", "/command", "/cmd", "/loader", "/payload",
    "/update", "/upload", "/exfil", "/collect", "/dump", "/steal",
    "/keylog", "/screenshot", "/api/task", "/api/checkin",
    "/api/config", "/api/update", "/api/v1/task", "/api/v1/checkin",
    "/api/v1/config", "/api/v1/update", "/heartbeat", "/telemetry",
    "/register", "/init", "/sync"
]

DANGEROUS_EXTS = [
    ".exe", ".dll", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".bat", ".cmd", ".scr", ".msi", ".jar", ".lnk",
    ".iso", ".cab"
]

RISKY_UA = [
    "powershell", "pwsh", "curl", "wget", "python-requests",
    "go-http-client", "winhttp", "bits", "microsoft bits"
]

WEAK_WORDS = [
    "c2", "evil", "beacon", "bot", "botnet", "malware",
    "payload", "command", "pastebin", "telegram", "discord",
    "webhook"
]

BENIGN_DOMAIN_EXACT = {
    "ctldl.windowsupdate.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "self.events.data.microsoft.com",
    "events.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "watson.events.data.microsoft.com",
    "fs.microsoft.com",
    "ecs.office.com",
    "assets.msn.com",
    "img-s-msn-com.akamaized.net",
    "controlplane.tailscale.com",
}

BENIGN_DOMAIN_SUFFIXES = (
    ".windowsupdate.com",
    ".msftconnecttest.com",
    ".events.data.microsoft.com",
    ".data.microsoft.com",
    ".microsoft.com",
    ".office.com",
    ".msn.com",
    ".akamaized.net",
    ".tailscale.com",
)

COMMON_BACKGROUND_PORTS = {53, 80, 443}

def is_benign_domain(domain):
    d = clean_text(domain, 255).lower().strip(".")
    if not d:
        return False
    return d in BENIGN_DOMAIN_EXACT or any(d.endswith(suffix) for suffix in BENIGN_DOMAIN_SUFFIXES)

HIGH_RISK_PORTS = {21, 22, 25, 853, 4443, 6667, 8000, 8080, 8443, 8888, 9001}

HTTP_BEACON = {}
DNS_NX = {}
CONN_BEACON = {}

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    line = f"[{now()}] {msg}"
    print(line, flush=True)
    with open(RESPONSE_LOG, "a") as f:
        f.write(line + "\n")

def observe(msg):
    line = f"[{now()}] {msg}"
    print(line, flush=True)
    with open(OBSERVE_LOG, "a") as f:
        f.write(line + "\n")

def clean_text(s, max_len=255):
    if not s or s == "-":
        return ""
    s = str(s).strip()
    s = re.sub(r'[^A-Za-z0-9._:/?&=%+\-@]', '', s)
    return s[:max_len]

def esc(s):
    return clean_text(s).replace("\\", "\\\\").replace('"', '\\"')

def parse_float(x, default=0.0):
    try:
        if x in ["", "-"]:
            return default
        return float(x)
    except Exception:
        return default

def parse_int(x, default=0):
    try:
        if x in ["", "-"]:
            return default
        return int(float(x))
    except Exception:
        return default

def ensure_files():
    RULE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BASE_RULE_FILE.touch(exist_ok=True)
    AUTO_RULE_FILE.touch(exist_ok=True)
    ACTIVE_RULE_FILE.touch(exist_ok=True)
    IOC_DOMAIN_FILE.touch(exist_ok=True)
    IOC_IP_FILE.touch(exist_ok=True)
    RESPONSE_LOG.touch(exist_ok=True)
    OBSERVE_LOG.touch(exist_ok=True)
    TLS_EVIDENCE_LOG.touch(exist_ok=True)

def read_set(path):
    items = set()
    if not path.exists():
        return items
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        items.add(line)
    return items

def load_db():
    db = {"next_sid": START_SID, "rules": {}}
    if SID_DB_FILE.exists():
        try:
            loaded = json.loads(SID_DB_FILE.read_text())
            if isinstance(loaded, dict):
                db.update(loaded)
        except Exception:
            pass
    try:
        db["next_sid"] = int(db.get("next_sid", START_SID))
    except Exception:
        db["next_sid"] = START_SID
    if not isinstance(db.get("rules"), dict):
        db["rules"] = {}
    return db

def save_db(db):
    SID_DB_FILE.write_text(json.dumps(db, indent=2))

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def validate_rule_file(rule_file):
    cmd = f"snort -c /usr/local/etc/snort/snort.lua -R {rule_file} -T"
    result = run_cmd(cmd)
    if result.returncode == 0:
        log("[OK] Snort validation passed")
        return True
    log("[ERROR] Snort validation failed")
    log(result.stdout[-2000:])
    return False

def rebuild_active_rules_to_file(auto_content, output_file):
    base = BASE_RULE_FILE.read_text() if BASE_RULE_FILE.exists() else ""
    Path(output_file).write_text(base + "\n" + auto_content + "\n")

def rebuild_all_rule_sets():
    script = "/usr/local/bin/rebuild_snort_rule_sets.sh"
    if Path(script).exists():
        result = run_cmd(f"bash {script}")
        if result.returncode == 0:
            log("[REBUILD] active_ids.rules and active_ips.rules rebuilt")
            out = result.stdout.strip()
            if out:
                log(out[-1200:])
            return True
        log("[ERROR] rebuild_snort_rule_sets.sh failed")
        log(result.stdout[-1600:])
        return False

    log("[WARN] rebuild script missing; fallback active_ips only")
    rebuild_active_rules_to_file(AUTO_RULE_FILE.read_text(), ACTIVE_RULE_FILE)
    return True

def committed_rule_present(db, rule_key):
    rec = db.get("rules", {}).get(rule_key)
    if not rec:
        return False

    auto_text = AUTO_RULE_FILE.read_text(errors="ignore") if AUTO_RULE_FILE.exists() else ""
    sid = str(rec.get("sid", "")).strip()
    saved_rule = str(rec.get("rule", "")).strip()

    if sid and f"sid:{sid};" in auto_text:
        return True
    if saved_rule and saved_rule in auto_text:
        return True
    return False


def commit_rule(rule_key, rule_template, evidence):
    db = load_db()
    db.setdefault("rules", {})
    if committed_rule_present(db, rule_key):
        return False
    if rule_key in db.get("rules", {}):
        log(f"[REPAIR] {rule_key} exists in SID DB but is missing from local_auto.rules; regenerating")
        db["rules"].pop(rule_key, None)

    sid = db["next_sid"]
    db["next_sid"] += 1
    rule = rule_template.replace("SID_PLACEHOLDER", str(sid))

    old_auto = AUTO_RULE_FILE.read_text() if AUTO_RULE_FILE.exists() else ""
    new_auto = old_auto + rule + "\n"

    tmp_auto = Path("/tmp/local_auto_v2.rules.tmp")
    tmp_active = Path("/tmp/active_ips_v2.rules.tmp")

    tmp_auto.write_text(new_auto)
    rebuild_active_rules_to_file(new_auto, tmp_active)

    log("---------------------------------------------------------")
    log(f"[DETECT-V2] {rule_key}")
    log(f"[EVIDENCE] {evidence}")
    log(f"[GENERATE] SID {sid}")
    log(f"[RULE] {rule}")

    if not validate_rule_file(tmp_active):
        log(f"[SKIP] SID {sid} not committed")
        return False

    shutil.move(str(tmp_auto), str(AUTO_RULE_FILE))
    try:
        tmp_active.unlink()
    except Exception:
        pass

    db["rules"][rule_key] = {
        "sid": sid,
        "created_at": now(),
        "evidence": evidence,
        "rule": rule
    }
    save_db(db)

    log(f"[COMMIT] Rule SID {sid} saved to {AUTO_RULE_FILE}")
    rebuild_all_rule_sets()
    log("[INFO] Snort watcher should reload active_ips.rules automatically")
    log("---------------------------------------------------------")
    return True

class ZeekLogWatcher:
    def __init__(self, path):
        self.path = Path(path)
        self.fields = []
        self.offset = 0
        self.ready = False

    def initialize(self):
        if not self.path.exists():
            return
        with open(self.path, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("#fields"):
                    self.fields = line.rstrip("\n").split("\t")[1:]
            # Terminal 1 cleans Zeek logs before startup, so read from
            # the beginning on first load. This prevents missing the first
            # HTTP request if the user tests immediately after READY.
            self.offset = 0
        if self.fields:
            self.ready = True
            log(f"[WATCH] {self.path.name} loaded from beginning")

    def read_new_events(self):
        events = []
        if not self.path.exists():
            return events
        if not self.ready:
            self.initialize()
            return events
        if self.path.stat().st_size < self.offset:
            self.fields = []
            self.offset = 0
            self.ready = False
            self.initialize()
            return events

        with open(self.path, "r", errors="ignore") as f:
            f.seek(self.offset)
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.startswith("#fields"):
                    self.fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                values = line.split("\t")
                if len(values) >= len(self.fields):
                    events.append(dict(zip(self.fields, values)))
            self.offset = f.tell()
        return events

def uri_base(uri):
    uri = clean_text(uri)
    if not uri:
        return ""
    return uri.split("?")[0]

def is_ip(s):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s or ""))

def entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((n/total) * math.log2(n/total) for n in freq.values())

def domain_score(domain):
    d = clean_text(domain, 255).lower().strip(".")
    if not d:
        return "allow", 0, []
    if is_ip(d):
        return "allow", 0, []
    if d.endswith("in-addr.arpa") or d.endswith("ip6.arpa"):
        return "allow", 0, ["reverse_dns_lookup"]
    if is_benign_domain(d):
        return "allow", 0, ["benign_background_domain"]

    ioc_domains = read_set(IOC_DOMAIN_FILE)
    if d in ioc_domains:
        return "block", 10, ["ioc_domain"]

    labels = d.split(".")
    longest = max([len(x) for x in labels]) if labels else 0
    first = labels[0] if labels else d

    score = 0
    reasons = []

    if len(d) >= 70:
        score += 3
        reasons.append("very_long_domain")
    if longest >= 40:
        score += 3
        reasons.append("very_long_label")
    if re.search(r"[A-Za-z0-9_-]{32,}", d):
        score += 3
        reasons.append("encoded_like_label")
    if entropy(first) >= 4.0 and len(first) >= 18:
        score += 3
        reasons.append("high_entropy_label")
    digit_ratio = sum(c.isdigit() for c in first) / max(len(first), 1)
    if len(first) >= 12 and digit_ratio >= 0.35:
        score += 2
        reasons.append("digit_heavy_label")
    if len(labels) >= 5:
        score += 2
        reasons.append("many_subdomains")

    for w in WEAK_WORDS:
        if w in d:
            score += 1
            reasons.append(f"weak_keyword:{w}")

    if score >= 5:
        return "block", score, reasons
    if score >= 2:
        return "observe", score, reasons
    return "allow", score, reasons

def make_http_rule(host, uri, msg):
    host = esc(host)
    uri = esc(uri_base(uri))

    if host and uri and uri != "/":
        return (
            f'{RULE_ACTION} tcp {HOME_NET} any -> any any '
            f'(msg:"{msg}"; flow:to_server,established; '
            f'http_header; content:"Host|3A|",nocase; content:"{host}",nocase; '
            f'http_uri; content:"{uri}",nocase; '
            f'sid:SID_PLACEHOLDER; rev:1;)'
        )

    if host:
        return (
            f'{RULE_ACTION} tcp {HOME_NET} any -> any any '
            f'(msg:"{msg}"; flow:to_server,established; '
            f'http_header; content:"Host|3A|",nocase; content:"{host}",nocase; '
            f'sid:SID_PLACEHOLDER; rev:1;)'
        )

    if uri and uri != "/":
        return (
            f'{RULE_ACTION} tcp {HOME_NET} any -> any any '
            f'(msg:"{msg}"; flow:to_server,established; '
            f'http_uri; content:"{uri}",nocase; '
            f'sid:SID_PLACEHOLDER; rev:1;)'
        )

    return None

def handle_http(event):
    src = event.get("id.orig_h", "")
    if src != LAN_CLIENT:
        return

    ts = parse_float(event.get("ts", "0"))
    host = clean_text(event.get("host", ""))
    uri = clean_text(event.get("uri", ""))
    ua = clean_text(event.get("user_agent", ""))
    method = clean_text(event.get("method", ""))
    base = uri_base(uri)
    body_len = parse_int(event.get("request_body_len", "0"))

    if is_benign_domain(host):
        return

    score = 0
    reasons = []

    base_l = base.lower()
    uri_l = uri.lower()
    ua_l = ua.lower()
    method_u = method.upper()

    for x in BAD_URI_KEYWORDS:
        if base_l.startswith(x) or x in base_l:
            score += 5
            reasons.append(f"bad_uri:{x}")
            break

    for ext in DANGEROUS_EXTS:
        if base_l.endswith(ext) or f"{ext}?" in uri_l:
            score += 5
            reasons.append(f"dangerous_download:{ext}")
            break

    if re.search(r"[?&](bot|bot_id|victim|hwid|guid|uuid|uid|machine|hostname|username|campaign|session|token|key)=", uri_l):
        score += 2
        reasons.append("bot_or_victim_identifier")

    for x in RISKY_UA:
        if x in ua_l:
            score += 1
            reasons.append(f"risky_ua:{x}")
            break

    host_action, host_score, host_reasons = domain_score(host)
    if host_action == "block":
        score += 5
        reasons.extend([f"host:{r}" for r in host_reasons])
    elif host_action == "observe":
        score += 2
        reasons.extend([f"host:{r}" for r in host_reasons])

    if method_u == "POST" and body_len >= 5000:
        score += 3
        reasons.append(f"large_post:{body_len}")

    if method_u == "POST" and any("bad_uri" in r for r in reasons):
        score += 2
        reasons.append("post_to_c2_like_uri")

    if not ua:
        score += 1
        reasons.append("empty_user_agent")

    # Repeated HTTP beacon pattern
    key = f"{host}|{base}|{ua_l}"
    if ts > 0 and host and base:
        arr = HTTP_BEACON.get(key, [])
        arr = [x for x in arr if ts - x <= 300]
        arr.append(ts)
        HTTP_BEACON[key] = arr
        if len(arr) >= 5:
            score += 5
            reasons.append(f"repeated_http_beacon:{len(arr)}_hits_5min")

    evidence = f"src={src} method={method} host={host} uri={uri} ua={ua} body_len={body_len} score={score} reasons={','.join(reasons)}"

    if score >= 5:
        rule = make_http_rule(host, base, "AUTO-V2 block correlated HTTP malware/C2 behavior")
        if rule:
            rule_key = f"http_v2:{host.lower()}:{base.lower()}"
            commit_rule(rule_key, rule, evidence)
        else:
            observe(f"[HTTP-HIGH] {evidence}")
    elif score >= 2:
        observe(f"[HTTP-OBSERVE] {evidence}")

def make_dns_rule(domain, msg):
    q = esc(domain)
    return (
        f'{RULE_ACTION} udp {HOME_NET} any -> any 53 '
        f'(msg:"{msg}"; content:"{q}",nocase; '
        f'sid:SID_PLACEHOLDER; rev:1;)'
    )

def handle_dns(event):
    src = event.get("id.orig_h", "")
    if src != LAN_CLIENT:
        return

    ts = parse_float(event.get("ts", "0"))
    query = clean_text(event.get("query", ""), 255).lower().strip(".")
    rcode = clean_text(event.get("rcode_name", ""))

    if not query:
        return
    if is_benign_domain(query):
        return

    action, score, reasons = domain_score(query)
    evidence = f"src={src} query={query} rcode={rcode} score={score} reasons={','.join(reasons)}"

    if action == "block":
        rule = make_dns_rule(query, "AUTO-V2 block suspicious/IOC DNS query")
        commit_rule(f"dns_v2:{query}", rule, evidence)
    elif action == "observe":
        observe(f"[DNS-OBSERVE] {evidence}")

    # NXDOMAIN burst = possible DGA
    if rcode.upper() == "NXDOMAIN" and ts > 0:
        arr = DNS_NX.get(src, [])
        arr = [(t, q) for t, q in arr if ts - t <= 300]
        arr.append((ts, query))
        DNS_NX[src] = arr
        unique = len(set(q for _, q in arr))
        if unique >= 8:
            observe(f"[DNS-DGA-POSSIBLE] src={src} unique_nxdomain_5min={unique}")

def handle_ssl(event):
    src = event.get("id.orig_h", "")
    if src != LAN_CLIENT:
        return

    sni = clean_text(event.get("server_name", ""), 255).lower().strip(".")
    if not sni:
        return
    if is_benign_domain(sni):
        return

    action, score, reasons = domain_score(sni)
    line = f"src={src} sni={sni} action={action} score={score} reasons={','.join(reasons)} limitation=https_metadata_only"

    if action in ["block", "observe"]:
        observe(f"[TLS-SNI] {line}")
        with open(TLS_EVIDENCE_LOG, "a") as f:
            f.write(f"{now()} {line}\n")

    # Do not generate raw TLS/SNI Snort rule. Instead, if SNI is high confidence,
    # generate DNS block rule so future resolution of same domain is blocked.
    if action == "block":
        rule = make_dns_rule(sni, "AUTO-V2 block DNS for suspicious TLS SNI domain")
        commit_rule(f"sni_dns_v2:{sni}", rule, line)

def handle_conn(event):
    src = event.get("id.orig_h", "")
    if src != LAN_CLIENT:
        return

    ts = parse_float(event.get("ts", "0"))
    dst = clean_text(event.get("id.resp_h", ""))
    port = parse_int(event.get("id.resp_p", "0"))
    proto = clean_text(event.get("proto", ""))
    duration = parse_float(event.get("duration", "0"))
    orig_bytes = parse_int(event.get("orig_bytes", "0"))
    resp_bytes = parse_int(event.get("resp_bytes", "0"))

    if not dst or port == 0:
        return

    # DNS/HTTP/HTTPS are explained by protocol logs. Do not let normal Windows
    # background traffic become generic beacon spam in the teaching terminal.
    if port in COMMON_BACKGROUND_PORTS:
        return

    if port in HIGH_RISK_PORTS:
        observe(f"[CONN-HIGH-RISK-PORT] src={src} dst={dst} port={port} proto={proto} duration={duration} orig_bytes={orig_bytes} resp_bytes={resp_bytes}")

    # Repeated small connections = possible beacon
    if ts > 0:
        key = f"{dst}:{port}:{proto}"
        arr = CONN_BEACON.get(key, [])
        arr = [x for x in arr if ts - x <= 300]
        arr.append(ts)
        CONN_BEACON[key] = arr

        small = (orig_bytes <= 2048 and resp_bytes <= 8192)
        if len(arr) >= 6 and small:
            observe(f"[CONN-BEACON-POSSIBLE] src={src} dst={dst} port={port} proto={proto} hits_5min={len(arr)} small_bytes={small}")

def main():
    import sys

    if os.geteuid() != 0:
        print("[ERROR] Run with sudo")
        raise SystemExit(1)

    if len(sys.argv) < 2:
        print("Usage: sudo python3 zeek_auto_rule_engine_v2.py /path/to/zeek/logdir")
        raise SystemExit(1)

    zeek_dir = Path(sys.argv[1])
    ensure_files()
    rebuild_all_rule_sets()

    log("=========================================================")
    log("ZEEK AUTO RULE ENGINE V2 STARTED")
    log(f"Zeek log dir: {zeek_dir}")
    log(f"Base rules: {BASE_RULE_FILE}")
    log(f"Auto rules: {AUTO_RULE_FILE}")
    log(f"IOC domains: {IOC_DOMAIN_FILE}")
    log(f"IOC IPs: {IOC_IP_FILE}")
    log("=========================================================")

    watchers = [
        ZeekLogWatcher(zeek_dir / "http.log"),
        ZeekLogWatcher(zeek_dir / "dns.log"),
        ZeekLogWatcher(zeek_dir / "ssl.log"),
        ZeekLogWatcher(zeek_dir / "conn.log"),
    ]

    handlers = {
        "http.log": handle_http,
        "dns.log": handle_dns,
        "ssl.log": handle_ssl,
        "conn.log": handle_conn,
    }

    while True:
        for watcher in watchers:
            events = watcher.read_new_events()
            handler = handlers.get(watcher.path.name)
            if handler:
                for event in events:
                    handler(event)
        time.sleep(1)

if __name__ == "__main__":
    main()
