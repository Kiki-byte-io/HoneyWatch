import os
import glob
import json
from datetime import datetime
from db_client import db

LOG_GLOB = os.getenv(
    "COWRIE_LOG_GLOB",
    "/home/kiki-victim/cowrie-honeypot-capture/cowrie/var/log/cowrie/cowrie.json*"
)
# Also check local path fallback
LOCAL_LOG_GLOB = os.path.join(os.path.dirname(__file__), "cowrie*.json*")


def parse_timestamp(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return ts


def load_events(paths):
    events = []
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
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
    if not log_files:
        log_files = sorted(glob.glob(LOCAL_LOG_GLOB))
    
    print(f"Found {len(log_files)} log files: {log_files}")
    if not log_files:
        print("No log files matched glob patterns.")
        return

    events = load_events(log_files)
    print(f"Loaded {len(events)} total events.")

    sessions = {}
    login_attempts = []
    commands = []

    for e in events:
        eid = e.get("eventid", "")
        sid = e.get("session")
        if not sid:
            continue

        ts_str = str(parse_timestamp(e.get("timestamp"))) if e.get("timestamp") else None

        if eid == "cowrie.session.connect":
            sessions[sid] = {
                "session_id": sid,
                "src_ip": e.get("src_ip"),
                "src_port": e.get("src_port"),
                "dst_port": e.get("dst_port"),
                "start_time": ts_str,
                "end_time": None,
                "duration_ms": None
            }

        elif eid == "cowrie.session.closed":
            if sid in sessions:
                sessions[sid]["end_time"] = ts_str
                sessions[sid]["duration_ms"] = e.get("duration_ms")
            else:
                sessions[sid] = {
                    "session_id": sid,
                    "src_ip": None,
                    "src_port": None,
                    "dst_port": None,
                    "start_time": None,
                    "end_time": ts_str,
                    "duration_ms": e.get("duration_ms")
                }

        elif eid in ("cowrie.login.success", "cowrie.login.failed"):
            login_attempts.append({
                "session_id": sid,
                "username": e.get("username"),
                "password": e.get("password"),
                "success": 1 if eid == "cowrie.login.success" else 0,
                "timestamp": ts_str
            })

        elif eid == "cowrie.command.input":
            commands.append({
                "session_id": sid,
                "input": e.get("input"),
                "timestamp": ts_str
            })

    session_insert = """
        INSERT INTO sessions (session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    for s in sessions.values():
        db.execute_query(session_insert, (
            s["session_id"], s["src_ip"], s["src_port"], s["dst_port"],
            s["start_time"], s["end_time"], s["duration_ms"]
        ), fetch=None)
    print(f"Processed {len(sessions)} sessions.")

    login_insert = """
        INSERT INTO login_attempts (session_id, username, password, success, timestamp)
        VALUES (%s, %s, %s, %s, %s)
    """
    inserted_logins = 0
    for l in login_attempts:
        db.execute_query(login_insert, (
            l["session_id"], l["username"], l["password"], l["success"], l["timestamp"]
        ), fetch=None)
        inserted_logins += 1

    command_insert = """
        INSERT INTO commands (session_id, input, timestamp)
        VALUES (%s, %s, %s)
    """
    inserted_commands = 0
    for c in commands:
        db.execute_query(command_insert, (
            c["session_id"], c["input"], c["timestamp"]
        ), fetch=None)
        inserted_commands += 1

    print(f"Inserted {inserted_logins} login attempts, {inserted_commands} commands.")


if __name__ == "__main__":
    main()
