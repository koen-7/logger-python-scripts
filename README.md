# OPNsense Log Dashboard

Live web dashboard for Suricata, Squid, and DNS block logs from OPNsense, with Headscale user mapping.

---

## How logs are collected

| Source | Method |
|---|---|
| **Suricata** | OPNsense syslog-ng forwards logs → target-machine UDP port 5140 |
| **Squid** | SSH tail of `/var/log/squid/access.log` on OPNsense |
| **DNS blocks** | OPNsense syslog-ng forwards Unbound logs → target-machine UDP port 5141 |
| **Usernames** | Headscale API polled every 5 minutes, IPs mapped to users |

---

## OPNsense config files

**`/usr/local/etc/syslog-ng.conf.d/suricata-remote.conf`** — forwards Suricata to target-machine:5140

**`/usr/local/etc/syslog-ng.conf.d/dns-remote.conf`** — forwards Unbound DNS to target-machine:5141

**`/usr/local/etc/rc.syshook.d/start/99-squid-syslog.sh`** — ensures SSH tail user has access after reboots

---

## Project structure

```
logger/
├── collector.py      # Collects all logs + Headscale user mapping
├── app.py            # Flask API + serves the dashboard
├── logs.db           # SQLite database (auto-created)
└── templates/
    └── index.html    # Dashboard UI
```

---

## Setup

```bash
# 1. Install dependencies
pip install flask paramiko requests

# 2. Set up SSH key auth to OPNsense (for Squid)
ssh-keygen -t ed25519 -f ~/.ssh/opnsense_key
ssh-copy-id -i ~/.ssh/opnsense_key.pub root@OPNsenseC2.project.home

# 3. Edit the config block at the top of collector.py with your values

# 4. Run
python3 collector.py   # terminal 1
python3 app.py         # terminal 2

# 5. Open browser at http://localhost:8080
```

---

## Ports used

| Port | Protocol | Purpose |
|---|---|---|
| 5140 | UDP | Suricata syslog from OPNsense |
| 5141 | UDP | Unbound DNS syslog from OPNsense |
| 8080 | TCP | Web dashboard |
