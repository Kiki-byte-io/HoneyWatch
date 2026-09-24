from flask import Flask, render_template, jsonify
import mysql.connector
import os

app = Flask(__name__)

DB_CONFIG = {
    "host": os.getenv("COWRIE_DB_HOST", "localhost"),
    "user": os.getenv("COWRIE_DB_USER", "cowrie_app"),
    "password": os.getenv("COWRIE_DB_PASSWORD"),
    "database": os.getenv("COWRIE_DB_NAME", "cowrie_logs")
}


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


@app.route("/")
def dashboard():
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT COUNT(*) AS count FROM sessions")
    total_sessions = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM login_attempts")
    total_logins = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM commands")
    total_commands = cur.fetchone()["count"]

    cur.execute("""
        SELECT COUNT(DISTINCT src_ip) AS count
        FROM sessions
        WHERE src_ip IS NOT NULL
    """)
    unique_attackers = cur.fetchone()["count"]

    cur.execute("""
        SELECT
            s.session_id,
            s.src_ip,
            s.dst_port,
            s.start_time,
            s.end_time,
            s.duration_ms,
            la.username,
            la.success
        FROM sessions s
        LEFT JOIN login_attempts la
            ON s.session_id = la.session_id
        ORDER BY s.start_time DESC
        LIMIT 20
    """)
    sessions = cur.fetchall()

    cur.execute("""
        SELECT session_id, input, timestamp
        FROM commands
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    commands = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        total_sessions=total_sessions,
        total_logins=total_logins,
        total_commands=total_commands,
        unique_attackers=unique_attackers,
        sessions=sessions,
        commands=commands
    )


@app.route("/api/stats")
def stats():
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT COUNT(*) AS count FROM sessions")
    sessions = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM login_attempts")
    logins = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM commands")
    commands = cur.fetchone()["count"]

    cur.execute("""
        SELECT COUNT(DISTINCT src_ip) AS count
        FROM sessions
        WHERE src_ip IS NOT NULL
    """)
    attackers = cur.fetchone()["count"]

    cur.close()
    conn.close()

    return jsonify({
        "sessions": sessions,
        "logins": logins,
        "commands": commands,
        "attackers": attackers
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
