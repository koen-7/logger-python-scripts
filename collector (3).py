"""
collector.py — collects Squid logs via SSH tail, Suricata via syslog UDP,
               DNS blocks via tshark, and maps IPs to users via Headscale API
Run with sudo (tshark needs root for packet capture)
"""

import threading
import socket
import sqlite3
import re
import time
import json
import logging
import requests
from datetime import datetime, timezone

# ─── CONFIG ────────────────────────────────────────────────────────────────────
OPNSENSE_HOST  = "OPNsenseC2.project.home"
OPNSENSE_USER  = "root"
OPNSENSE_KEY   = "/home/kaliuser/.ssh/opnsense_key"
SQUID_LOG_PATH = "/var/log/squid/access.log"

SYSLOG_BIND_IP = "0.0.0.0"
SYSLOG_PORT    = 5140
DNS_SYSLOG_PORT = 5141    # UDP port for Unbound DNS syslog from OPNsense

HEADSCALE_URL     = "https://headscale.project.home"
HEADSCALE_API_KEY = "hskey-api-qLRDrbWOu7nA-TRUtgaHWQXOn47MLIOg0nOwI2BIbyNy7mfcZJMvSW3_RDiTjRXmfD1cv27SnQNti"
HEADSCALE_REFRESH = 300   # seconds between Headscale IP→user map refreshes

DB_PATH = "logs.db"
# ───────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


# ─── HEADSCALE IP→USER MAP ─────────────────────────────────────────────────────
# Shared dict: { "100.64.0.5": "alice", "100.64.0.6": "bob", ... }
_ip_user_map: dict = {}
_ip_user_lock = threading.Lock()


def refresh_headscale_map():
    """Fetch nodes from Headscale and rebuild the IP→username map."""
    try:
        headers  = {"Authorization": f"Bearer {HEADSCALE_API_KEY}"}
        response = requests.get(
            f"{HEADSCALE_URL}/api/v1/node",
            headers=headers,
            verify=False,
            timeout=10
        )
        response.raise_for_status()
        nodes    = response.json().get("nodes", [])
        new_map  = {}
        for node in nodes:
            user = node.get("user", {}).get("name", "unknown")
            for ip in node.get("ipAddresses", []):
                new_map[ip] = user
        with _ip_user_lock:
            _ip_user_map.clear()
            _ip_user_map.update(new_map)
        log.info("Headscale map refreshed: %d IPs mapped to users", len(new_map))
    except Exception as e:
        log.warning("Headscale refresh failed: %s", e)


def lookup_user(ip: str) -> str:
    """Return username for an IP, or empty string if not found."""
    with _ip_user_lock:
        return _ip_user_map.get(ip, "")


def headscale_refresher():
    """Background thread that keeps the IP→user map fresh."""
    while True:
        refresh_headscale_map()
        time.sleep(HEADSCALE_REFRESH)


# ─── DATABASE ──────────────────────────────────────────────────────────────────

def get_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = get_db()
    con.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT,
            source    TEXT,
            severity  TEXT,
            src_ip    TEXT,
            src_user  TEXT,
            dst_ip    TEXT,
            port      TEXT,
            message   TEXT,
            raw       TEXT
        )
    """)
    # Add src_user column if upgrading from older DB without it
    try:
        con.execute("ALTER TABLE logs ADD COLUMN src_user TEXT DEFAULT ''")
        log.info("Added src_user column to existing database")
    except Exception:
        pass  # column already exists
    con.execute("CREATE INDEX IF NOT EXISTS idx_source   ON logs(source)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ts       ON logs(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_src_user ON logs(src_user)")
    con.commit()
    con.close()
    log.info("Database ready: %s", DB_PATH)


def insert_log(ts, source, severity, src_ip, dst_ip, port, message, raw=""):
    src_user = lookup_user(src_ip)
    try:
        con = get_db()
        con.execute(
            "INSERT INTO logs(ts,source,severity,src_ip,src_user,dst_ip,port,message,raw) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, source, severity, src_ip, src_user, dst_ip, port, message, raw)
        )
        con.commit()
        con.close()
    except Exception as e:
        log.error("DB insert error: %s", e)


# ─── SQUID PARSER ──────────────────────────────────────────────────────────────
SQUID_RE = re.compile(
    r"^(\d+\.\d+)\s+\d+\s+(\S+)\s+(\S+)/(\d+)\s+\d+\s+(\S+)\s+(\S+)"
)

def parse_squid_line(line: str):
    m = SQUID_RE.match(line.strip())
    if not m:
        return
    epoch, client_ip, action, status, method, url = m.groups()
    try:
        ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    severity = "blocked" if action.startswith("DENIED") or status == "403" else "access"
    message  = f"{method} {url} [{action}/{status}]"
    insert_log(ts, "squid", severity, client_ip, "-", "-", message, line.strip())


# ─── SURICATA PARSER ───────────────────────────────────────────────────────────
EVE_RE = re.compile(r"\{.*\}")

def normalize_ts(raw_ts):
    try:
        return datetime.fromisoformat(raw_ts).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def parse_suricata_syslog(data: str):
    m = EVE_RE.search(data)
    if not m:
        return
    try:
        evt = json.loads(m.group())
    except json.JSONDecodeError:
        return

    event_type = evt.get("event_type", "")
    ts         = normalize_ts(evt.get("timestamp", ""))
    src_ip     = evt.get("src_ip",  "-")
    dst_ip     = evt.get("dest_ip", "-")
    port       = str(evt.get("dest_port", "-"))

    if event_type == "alert":
        sig     = evt.get("alert", {}).get("signature", "unknown signature")
        severity = evt.get("alert", {}).get("severity", 2)
        sev_map = {1: "low", 2: "medium", 3: "high"}
        # ET INFO rules are always low
        if sig.startswith("ET INFO") or evt.get("alert", {}).get("category") == "Misc activity":
            sev_str = "low"
        else:
            sev_str = sev_map.get(int(severity), "medium")
        message = sig
    elif event_type == "dns":
        query   = evt.get("dns", {}).get("rrname", "-")
        sev_str = "dns"
        message = f"DNS query: {query}"
    elif event_type == "http":
        http    = evt.get("http", {})
        sev_str = "http"
        message = f"{http.get('http_method','-')} {http.get('hostname','-')}{http.get('url','-')}"
    elif event_type == "tls":
        tls     = evt.get("tls", {})
        sev_str = "tls"
        message = f"TLS {tls.get('version','-')} SNI={tls.get('sni','-')}"
    else:
        sev_str = event_type or "info"
        message = data[:200]

    insert_log(ts, "suricata", sev_str, src_ip, dst_ip, port, message, m.group())


# ─── COLLECTORS ────────────────────────────────────────────────────────────────

def collect_squid():
    while True:
        try:
            import paramiko
            log.info("Connecting to OPNsense via SSH for Squid tail...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(OPNSENSE_HOST, username=OPNSENSE_USER, key_filename=OPNSENSE_KEY, timeout=10)
            log.info("SSH connected. Tailing %s", SQUID_LOG_PATH)
            _, stdout, _ = client.exec_command(f"tail -F {SQUID_LOG_PATH}")
            for line in stdout:
                parse_squid_line(line)
        except ImportError:
            log.error("paramiko not installed. Run: pip install paramiko")
            time.sleep(60)
        except Exception as e:
            log.error("Squid SSH error: %s — retrying in 15s", e)
            time.sleep(15)


def collect_suricata():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_BIND_IP, SYSLOG_PORT))
    log.info("Listening for Suricata syslog on UDP %s:%d", SYSLOG_BIND_IP, SYSLOG_PORT)
    while True:
        try:
            data, _ = sock.recvfrom(65535)
            parse_suricata_syslog(data.decode("utf-8", errors="replace"))
        except Exception as e:
            log.error("Suricata syslog error: %s", e)


# Matches: info: 192.168.1.184 log.tailscale.com. AAAA IN NXDOMAIN ...
DNS_NXDOMAIN_RE = re.compile(
    r"info:\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+?)\.\s+\w+\s+IN\s+NXDOMAIN"
)

def parse_dns_syslog(data: str):
    if "NXDOMAIN" not in data:
        return
    m = DNS_NXDOMAIN_RE.search(data)
    if not m:
        return
    client_ip, domain = m.group(1), m.group(2)
    if "in-addr.arpa" in domain or "ip6.arpa" in domain:
        return
    if client_ip == "127.0.0.1":
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    insert_log(ts, "dns_block", "blocked", client_ip, "-", "53", f"BLOCKED: {domain}", data.strip())
    log.info("DNS block: %s blocked for %s", domain, client_ip)


def collect_dns_blocks():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", DNS_SYSLOG_PORT))
    log.info("Listening for Unbound DNS syslog on UDP port %d", DNS_SYSLOG_PORT)
    while True:
        try:
            data, _ = sock.recvfrom(65535)
            parse_dns_syslog(data.decode("utf-8", errors="replace"))
        except Exception as e:
            log.error("DNS syslog error: %s", e)


# ─── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()

    # Initial Headscale map load before starting collectors
    refresh_headscale_map()

    threads = [
        threading.Thread(target=headscale_refresher, daemon=True, name="headscale"),
        threading.Thread(target=collect_squid,        daemon=True, name="squid-ssh"),
        threading.Thread(target=collect_suricata,     daemon=True, name="suricata-syslog"),
        threading.Thread(target=collect_dns_blocks,   daemon=True, name="dns-syslog"),
    ]
    for t in threads:
        t.start()

    log.info("Collectors running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")
