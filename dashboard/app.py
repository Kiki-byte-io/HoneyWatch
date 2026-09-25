import os
import sys
import io
import csv
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, jsonify, request, Response, send_file
from db_client import db
from bot_human_classifier import get_bot_assessment
from evidence_analyzer import get_evidence
from ai_mitigation import generate_mitigations
from ai_summarizer import generate_summary
from report_generator import generate_pdf_report, fetch_report_data
from log_watcher import start_realtime_log_watcher

app = Flask(__name__, template_folder="templates", static_folder="static")

# Start automated real-time background log watcher thread (polls every 2s)
try:
    start_realtime_log_watcher(interval_seconds=2)
except Exception as e:
    print(f"[Realtime Log Watcher Warning] {e}")


COMMAND_MEANINGS = {
    "whoami": "Identifies current user account",
    "id": "Displays UID/GID and group memberships",
    "uname -a": "Displays OS kernel and system architecture",
    "ls -la": "Lists all files including hidden system files",
    "cat /etc/passwd": "Reads system account registry file",
    "wget": "Downloads remote file or payload",
    "curl": "Transfers data from remote HTTP server",
    "ps aux": "Lists all active processes running on host",
    "ifconfig": "Lists network interfaces and IP addresses",
    "history": "Inspects command history file",
    "exit": "Terminates honeypot session"
}


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/dashboard/summary")
def api_summary():
    try:
        s_count = db.execute_query("SELECT COUNT(*) AS count FROM sessions", fetch="one")
        tot_sessions = s_count["count"] if s_count else 0

        l_count = db.execute_query("SELECT COUNT(*) AS count FROM login_attempts", fetch="one")
        tot_logins = l_count["count"] if l_count else 0

        c_count = db.execute_query("SELECT COUNT(*) AS count FROM commands", fetch="one")
        tot_commands = c_count["count"] if c_count else 0

        ip_count = db.execute_query("SELECT COUNT(DISTINCT src_ip) AS count FROM sessions WHERE src_ip IS NOT NULL", fetch="one")
        unique_ips = ip_count["count"] if ip_count else 0

        recent_sessions = db.execute_query("""
            SELECT s.session_id, s.src_ip, s.dst_port, s.start_time, s.end_time, s.duration_ms,
                   la.username, la.success
            FROM sessions s
            LEFT JOIN login_attempts la ON s.session_id = la.session_id
            ORDER BY s.start_time DESC
            LIMIT 10
        """, fetch="all") or []

        recent_commands = db.execute_query("""
            SELECT session_id, input, timestamp
            FROM commands
            ORDER BY timestamp DESC
            LIMIT 15
        """, fetch="all") or []

        top_ips = db.execute_query("""
            SELECT src_ip, COUNT(*) AS count
            FROM sessions
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 5
        """, fetch="all") or []

        top_usernames = db.execute_query("""
            SELECT username, COUNT(*) AS count
            FROM login_attempts
            WHERE username IS NOT NULL AND username != ''
            GROUP BY username
            ORDER BY count DESC
            LIMIT 5
        """, fetch="all") or []

        top_commands = db.execute_query("""
            SELECT input, COUNT(*) AS count
            FROM commands
            WHERE input IS NOT NULL AND input != ''
            GROUP BY input
            ORDER BY count DESC
            LIMIT 5
        """, fetch="all") or []

        bot_assessment = get_bot_assessment()

        return jsonify({
            "status": "online",
            "db_connected": True,
            "total_sessions": tot_sessions,
            "total_logins": tot_logins,
            "total_commands": tot_commands,
            "unique_ips": unique_ips,
            "total_events": tot_sessions + tot_logins + tot_commands,
            "recent_sessions": recent_sessions,
            "recent_commands": recent_commands,
            "top_ips": top_ips,
            "top_usernames": top_usernames,
            "top_commands": top_commands,
            "bot_assessment": bot_assessment,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "db_connected": False,
            "error_message": f"Unable to connect to monitoring database: {str(e)}",
            "total_sessions": 0,
            "total_logins": 0,
            "total_commands": 0,
            "unique_ips": 0,
            "total_events": 0,
            "recent_sessions": [],
            "recent_commands": [],
            "top_ips": [],
            "top_usernames": [],
            "top_commands": [],
            "bot_assessment": get_bot_assessment(),
            "timestamp": datetime.now().isoformat()
        })


@app.route("/api/intelligence")
def api_intelligence():
    session_id = request.args.get("session_id")
    evidence = get_evidence(session_id=session_id)
    summary_data = generate_summary(evidence)
    mitigations = generate_mitigations(evidence)
    automation = get_bot_assessment()

    return jsonify({
        "summary": summary_data.get("summary"),
        "assessment": summary_data.get("assessment"),
        "mitigations": mitigations,
        "automation": {
            "assessment": automation.get("assessment"),
            "score": automation.get("automation_score"),
            "features": automation.get("behavioral_features"),
            "indicators": automation.get("indicators")
        },
        "evidence": evidence
    })


@app.route("/api/attacks")
def api_attacks():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 25))
    search = request.args.get("search", "").strip()
    ip_filter = request.args.get("ip", "").strip()
    event_type = request.args.get("event_type", "").strip()
    offset = (page - 1) * limit

    sessions = db.execute_query("""
        SELECT 'session_connect' AS event_type, session_id, src_ip, dst_port, start_time AS timestamp,
               NULL AS username, NULL AS success, NULL AS input
        FROM sessions
        WHERE start_time IS NOT NULL
    """, fetch="all") or []

    logins = db.execute_query("""
        SELECT CASE WHEN success=1 THEN 'login_success' ELSE 'login_failed' END AS event_type,
               l.session_id, s.src_ip, s.dst_port, l.timestamp, l.username, l.success, NULL AS input
        FROM login_attempts l
        LEFT JOIN sessions s ON l.session_id = s.session_id
    """, fetch="all") or []

    commands = db.execute_query("""
        SELECT 'command_input' AS event_type, c.session_id, s.src_ip, s.dst_port, c.timestamp,
               NULL AS username, NULL AS success, c.input
        FROM commands c
        LEFT JOIN sessions s ON c.session_id = s.session_id
    """, fetch="all") or []

    all_events = sessions + logins + commands

    def event_ts(e):
        return str(e.get("timestamp") or "")

    all_events.sort(key=event_ts, reverse=True)

    if search:
        search_lower = search.lower()
        all_events = [
            e for e in all_events
            if (e.get("src_ip") and search_lower in str(e["src_ip"]).lower())
            or (e.get("session_id") and search_lower in str(e["session_id"]).lower())
            or (e.get("username") and search_lower in str(e["username"]).lower())
            or (e.get("input") and search_lower in str(e["input"]).lower())
            or (e.get("event_type") and search_lower in str(e["event_type"]).lower())
        ]

    if ip_filter:
        all_events = [e for e in all_events if e.get("src_ip") == ip_filter]

    if event_type:
        all_events = [e for e in all_events if e.get("event_type") == event_type]

    total_count = len(all_events)
    paginated_events = all_events[offset: offset + limit]

    return jsonify({
        "total": total_count,
        "page": page,
        "limit": limit,
        "total_pages": (total_count + limit - 1) // limit if limit > 0 else 1,
        "events": paginated_events
    })


@app.route("/api/sessions")
def api_sessions():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    search = request.args.get("search", "").strip()
    offset = (page - 1) * limit

    query = """
        SELECT s.session_id, s.src_ip, s.src_port, s.dst_port, s.start_time, s.end_time, s.duration_ms,
               (SELECT COUNT(*) FROM login_attempts WHERE session_id = s.session_id) AS login_count,
               (SELECT COUNT(*) FROM commands WHERE session_id = s.session_id) AS command_count
        FROM sessions s
    """
    params = []
    if search:
        query += " WHERE s.session_id LIKE %s OR s.src_ip LIKE %s"
        params.extend([f"%{search}%", f"%{search}%"])

    query += " ORDER BY s.start_time DESC"

    all_sessions = db.execute_query(query, params=params if params else None, fetch="all") or []
    total_count = len(all_sessions)
    paginated = all_sessions[offset: offset + limit]

    return jsonify({
        "total": total_count,
        "page": page,
        "limit": limit,
        "sessions": paginated
    })


@app.route("/api/sessions/<session_id>")
def api_session_detail(session_id):
    session = db.execute_query(
        "SELECT session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms FROM sessions WHERE session_id = %s",
        params=(session_id,),
        fetch="one"
    )
    if not session:
        return jsonify({"error": "Session not found"}), 404

    logins = db.execute_query(
        "SELECT username, success, timestamp FROM login_attempts WHERE session_id = %s ORDER BY timestamp",
        params=(session_id,),
        fetch="all"
    ) or []

    commands = db.execute_query(
        "SELECT input, timestamp FROM commands WHERE session_id = %s ORDER BY timestamp",
        params=(session_id,),
        fetch="all"
    ) or []

    for c in commands:
        c["meaning"] = COMMAND_MEANINGS.get(c["input"], "Interactive command execution")

    return jsonify({
        "session": session,
        "logins": logins,
        "commands": commands
    })


@app.route("/api/ips")
def api_ips():
    ips = db.execute_query("""
        SELECT src_ip,
               COUNT(DISTINCT session_id) AS total_sessions,
               MIN(start_time) AS first_seen,
               MAX(start_time) AS last_seen
        FROM sessions
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY total_sessions DESC
    """, fetch="all") or []

    for item in ips:
        ip = item["src_ip"]
        l_cnt = db.execute_query(
            "SELECT COUNT(*) AS count FROM login_attempts l JOIN sessions s ON l.session_id = s.session_id WHERE s.src_ip = %s",
            params=(ip,),
            fetch="one"
        )
        c_cnt = db.execute_query(
            "SELECT COUNT(*) AS count FROM commands c JOIN sessions s ON c.session_id = s.session_id WHERE s.src_ip = %s",
            params=(ip,),
            fetch="one"
        )
        item["total_logins"] = l_cnt["count"] if l_cnt else 0
        item["total_commands"] = c_cnt["count"] if c_cnt else 0
        item["total_events"] = item["total_sessions"] + item["total_logins"] + item["total_commands"]

    return jsonify({"ips": ips})


@app.route("/api/ips/<ip>")
def api_ip_detail(ip):
    ip_sessions = db.execute_query(
        "SELECT session_id, src_port, dst_port, start_time, end_time, duration_ms FROM sessions WHERE src_ip = %s ORDER BY start_time DESC",
        params=(ip,),
        fetch="all"
    ) or []

    ip_logins = db.execute_query(
        "SELECT l.session_id, l.username, l.success, l.timestamp FROM login_attempts l JOIN sessions s ON l.session_id = s.session_id WHERE s.src_ip = %s ORDER BY l.timestamp DESC",
        params=(ip,),
        fetch="all"
    ) or []

    ip_commands = db.execute_query(
        "SELECT c.session_id, c.input, c.timestamp FROM commands c JOIN sessions s ON c.session_id = s.session_id WHERE s.src_ip = %s ORDER BY c.timestamp DESC",
        params=(ip,),
        fetch="all"
    ) or []

    return jsonify({
        "ip": ip,
        "sessions": ip_sessions,
        "logins": ip_logins,
        "commands": ip_commands
    })


@app.route("/api/commands")
def api_commands():
    commands = db.execute_query("""
        SELECT input, COUNT(*) AS frequency,
               MAX(timestamp) AS last_executed,
               COUNT(DISTINCT session_id) AS unique_sessions
        FROM commands
        WHERE input IS NOT NULL AND input != ''
        GROUP BY input
        ORDER BY frequency DESC
    """, fetch="all") or []

    for c in commands:
        c["meaning"] = COMMAND_MEANINGS.get(c["input"], "Standard shell command execution")

    return jsonify({"commands": commands})


@app.route("/api/credentials")
def api_credentials():
    usernames = db.execute_query("""
        SELECT username, COUNT(*) AS count,
               SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS success_count,
               SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failed_count
        FROM login_attempts
        WHERE username IS NOT NULL AND username != ''
        GROUP BY username
        ORDER BY count DESC
    """, fetch="all") or []

    return jsonify({
        "usernames": usernames
    })


@app.route("/api/timeline")
def api_timeline():
    sessions = db.execute_query("SELECT start_time AS timestamp, 'session' AS type FROM sessions WHERE start_time IS NOT NULL", fetch="all") or []
    logins = db.execute_query("SELECT timestamp, 'login' AS type FROM login_attempts WHERE timestamp IS NOT NULL", fetch="all") or []
    commands = db.execute_query("SELECT timestamp, 'command' AS type FROM commands WHERE timestamp IS NOT NULL", fetch="all") or []

    all_pts = sessions + logins + commands

    time_bins = {}
    for p in all_pts:
        ts = str(p.get("timestamp", ""))[:13]
        if not ts:
            continue
        if ts not in time_bins:
            time_bins[ts] = {"timestamp": ts + ":00", "sessions": 0, "logins": 0, "commands": 0, "total": 0}
        ttype = p.get("type")
        if ttype == "session":
            time_bins[ts]["sessions"] += 1
        elif ttype == "login":
            time_bins[ts]["logins"] += 1
        elif ttype == "command":
            time_bins[ts]["commands"] += 1
        time_bins[ts]["total"] += 1

    sorted_timeline = sorted(time_bins.values(), key=lambda x: x["timestamp"])
    return jsonify({"timeline": sorted_timeline})


@app.route("/api/classifier")
def api_classifier():
    return jsonify(get_bot_assessment())


@app.route("/api/logs")
def api_logs():
    events = db.execute_query("""
        SELECT 'session.connect' AS eventid, session_id, src_ip, dst_port, start_time AS timestamp
        FROM sessions
        ORDER BY start_time DESC
        LIMIT 100
    """, fetch="all") or []
    return jsonify({"logs": events})


@app.route("/api/report/preview")
def api_report_preview():
    range_filter = request.args.get("range", "all")
    report_data = fetch_report_data(range_filter)
    return jsonify(report_data)


@app.route("/api/report/pdf")
def api_report_pdf():
    try:
        range_filter = request.args.get("range", "all")
        pdf_bytes = generate_pdf_report(range_filter)
        buffer = io.BytesIO(pdf_bytes)
        date_str = datetime.now().strftime("%Y-%m-%d")
        filename = f"HoneyWatch_Executive_Report_{date_str}.pdf"

        response = send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return response
    except Exception as e:
        print(f"[PDF Generation Error] {e}")
        return jsonify({
            "error": "Executive report generation failed. Please try again.",
            "details": str(e)
        }), 500


@app.route("/api/export/csv")
def api_export_csv():
    sessions = db.execute_query("""
        SELECT s.session_id, s.src_ip, s.dst_port, s.start_time, s.end_time, s.duration_ms,
               la.username, la.success
        FROM sessions s
        LEFT JOIN login_attempts la ON s.session_id = la.session_id
        ORDER BY s.start_time DESC
    """, fetch="all") or []

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Session ID", "Source IP", "Destination Port", "Start Time", "End Time", "Duration (ms)", "Attempted Username", "Login Success"])

    for s in sessions:
        cw.writerow([
            s.get("session_id"),
            s.get("src_ip"),
            s.get("dst_port"),
            s.get("start_time"),
            s.get("end_time"),
            s.get("duration_ms"),
            s.get("username"),
            s.get("success")
        ])

    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="HoneyWatch_Attack_Data.csv"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
