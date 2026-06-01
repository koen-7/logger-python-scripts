"""
app.py — Flask web dashboard for OPNsense Suricata + Squid + DNS logs
"""

from flask import Flask, render_template, jsonify, request
import sqlite3

DB_PATH = "logs.db"
app = Flask(__name__)


def get_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def query(sql, args=()):
    con = get_db()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():
    source   = request.args.get("source", "")
    severity = request.args.get("severity", "")
    search   = request.args.get("search", "")
    limit    = min(int(request.args.get("limit", 200)), 1000)

    conditions, args = [], []

    if source:
        conditions.append("source = ?")
        args.append(source)
    if severity:
        conditions.append("severity = ?")
        args.append(severity)
    if search:
        conditions.append(
            "(message LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR src_user LIKE ?)"
        )
        args += [f"%{search}%"] * 4

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    args.append(limit)
    rows = query(f"SELECT * FROM logs {where} ORDER BY ts DESC LIMIT ?", args)
    return jsonify(rows)


@app.route("/api/stats")
def api_stats():
    totals = query("SELECT source, COUNT(*) as n FROM logs GROUP BY source")

    severities = query(
        "SELECT severity, COUNT(*) as n FROM logs GROUP BY severity ORDER BY n DESC"
    )

    # Top IPs with username attached
    top_ips = query(
        "SELECT src_ip, src_user, COUNT(*) as n FROM logs "
        "WHERE src_ip != '-' GROUP BY src_ip ORDER BY n DESC LIMIT 10"
    )

    timeline = query(
        "SELECT strftime('%Y-%m-%dT%H:00:00', ts) as hour, source, COUNT(*) as n "
        "FROM logs "
        "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%S', datetime('now', '-24 hours')) "
        "AND source IN ('suricata', 'squid', 'dns_block') "
        "GROUP BY hour, source ORDER BY hour"
    )

    alerts = query(
        "SELECT * FROM logs WHERE source='suricata' AND severity IN ('high','critical') "
        "ORDER BY ts DESC LIMIT 20"
    )

    # Top users by event count
    top_users = query(
        "SELECT src_user, COUNT(*) as n FROM logs "
        "WHERE src_user != '' GROUP BY src_user ORDER BY n DESC LIMIT 10"
    )

    return jsonify({
        "totals":     totals,
        "severities": severities,
        "top_ips":    top_ips,
        "timeline":   timeline,
        "alerts":     alerts,
        "top_users":  top_users,
    })


@app.route("/api/dns")
def api_dns():
    limit  = min(int(request.args.get("limit", 200)), 1000)
    search = request.args.get("search", "")

    conditions, args = ["source='dns_block'"], []
    if search:
        conditions.append("(message LIKE ? OR src_ip LIKE ? OR src_user LIKE ?)")
        args += [f"%{search}%"] * 3

    where = "WHERE " + " AND ".join(conditions)
    args.append(limit)
    rows = query(f"SELECT * FROM logs {where} ORDER BY ts DESC LIMIT ?", args)

    top_domains = query(
        "SELECT message, COUNT(*) as n FROM logs WHERE source='dns_block' "
        "GROUP BY message ORDER BY n DESC LIMIT 10"
    )

    top_clients = query(
        "SELECT src_ip, src_user, COUNT(*) as n FROM logs WHERE source='dns_block' "
        "GROUP BY src_ip ORDER BY n DESC LIMIT 10"
    )

    timeline = query(
        "SELECT strftime('%Y-%m-%dT%H:00:00', ts) as hour, COUNT(*) as n "
        "FROM logs WHERE source='dns_block' "
        "AND ts >= strftime('%Y-%m-%dT%H:%M:%S', datetime('now', '-24 hours')) "
        "GROUP BY hour ORDER BY hour"
    )

    total = query("SELECT COUNT(*) as n FROM logs WHERE source='dns_block'")[0]["n"]

    return jsonify({
        "logs": rows, "top_domains": top_domains,
        "top_clients": top_clients, "timeline": timeline, "total": total,
    })


@app.route("/api/clear", methods=["POST"])
def api_clear():
    con = get_db()
    con.execute("DELETE FROM logs")
    con.commit()
    con.close()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
