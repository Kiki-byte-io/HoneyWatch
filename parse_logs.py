import os
import glob
import json
import mysql.connector
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "user": "cowrie_app",
    "password": os.getenv("COWRIE_DB_PASSWORD"),
    "database": "cowrie_logs"
}

LOG_GLOB = "/home/kiki-victim/cowrie-honeypot-capture/cowrie/var/log/cowrie/cowrie.json*"


def parse_timestamp(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")


def load_events(paths):
    events = []
    for path in paths:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"Skipping malformed line in {path}: {line[:80]}...")
    return events


def main():
    log_files = sorted(glob.glob(LOG_GLOB))
    print(f"Found {len(log_files)} log files: {log_files}")
    events = load_events(log_files)
    print(f"Loaded {len(events)} total events.")

    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()

    sessions = {}
    login_attempts = []
    commands = []

    for e in events:
        eid = e.get("eventid", "")
        sid = e.get("session")

        if eid == "cowrie.session.connect":
            sessions[sid] = {
                "session_id": sid,
                "src_ip": e.get("src_ip"),
                "src_port": e.get("src_port"),
                "dst_port": e.get("dst_port"),
                "start_time": parse_timestamp(e["timestamp"]),
                "end_time": None,
                "duration_ms": None
            }

        elif eid == "cowrie.session.closed":
            if sid in sessions:
                sessions[sid]["end_time"] = parse_timestamp(e["timestamp"])
                sessions[sid]["duration_ms"] = e.get("duration_ms")
            else:
                print(f"Warning: session.closed for unknown session {sid}, creating stub row")
                sessions[sid] = {
                    "session_id": sid,
                    "src_ip": None,
                    "src_port": None,
                    "dst_port": None,
                    "start_time": None,
                    "end_time": parse_timestamp(e["timestamp"]),
                    "duration_ms": e.get("duration_ms")
                }

        elif eid in ("cowrie.login.success", "cowrie.login.failed"):
            login_attempts.append({
                "session_id": sid,
                "username": e.get("username"),
                "password": e.get("password"),
                "success": 1 if eid == "cowrie.login.success" else 0,
                "timestamp": parse_timestamp(e["timestamp"])
            })

        elif eid == "cowrie.command.input":
            commands.append({
                "session_id": sid,
                "input": e.get("input"),
                "timestamp": parse_timestamp(e["timestamp"])
            })

    session_insert = """
        INSERT INTO sessions (session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            end_time = COALESCE(VALUES(end_time), end_time),
            duration_ms = COALESCE(VALUES(duration_ms), duration_ms),
            src_ip = COALESCE(src_ip, VALUES(src_ip)),
            src_port = COALESCE(src_port, VALUES(src_port)),
            dst_port = COALESCE(dst_port, VALUES(dst_port)),
            start_time = COALESCE(start_time, VALUES(start_time))
    """
    for s in sessions.values():
        cur.execute(session_insert, (
            s["session_id"], s["src_ip"], s["src_port"], s["dst_port"],
            s["start_time"], s["end_time"], s["duration_ms"]
        ))
    conn.commit()
    print(f"Inserted/updated {len(sessions)} sessions.")

    login_insert = """
        INSERT INTO login_attempts (session_id, username, password, success, timestamp)
        VALUES (%s, %s, %s, %s, %s)
    """
    inserted_logins = 0
    for l in login_attempts:
        if l["session_id"] not in sessions:
            print(f"Skipping login attempt for unknown session {l['session_id']}")
            continue
        cur.execute(login_insert, (
            l["session_id"], l["username"], l["password"], l["success"], l["timestamp"]
        ))
        inserted_logins += 1

    command_insert = """
        INSERT INTO commands (session_id, input, timestamp)
        VALUES (%s, %s, %s)
    """
    inserted_commands = 0
    for c in commands:
        if c["session_id"] not in sessions:
            print(f"Skipping command for unknown session {c['session_id']}")
            continue
        cur.execute(command_insert, (
            c["session_id"], c["input"], c["timestamp"]
        ))
        inserted_commands += 1

    conn.commit()
    print(f"Inserted {inserted_logins} login attempts, {inserted_commands} commands.")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
