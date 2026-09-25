import os
import glob
import json
import time
import threading
from datetime import datetime
from db_client import db

LOG_GLOB = os.getenv(
    "COWRIE_LOG_GLOB",
    os.path.expanduser("~/cowrie-honeypot-capture/cowrie/var/log/cowrie/cowrie.json*")
)
LOCAL_LOG_GLOB = os.path.join(os.path.dirname(__file__), "cowrie*.json*")

PROCESSED_LINES = set()


def parse_timestamp(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return str(ts)


def process_event(e):
    eid = e.get("eventid", "")
    sid = e.get("session")
    if not sid:
        return

    ts_str = parse_timestamp(e.get("timestamp"))

    if eid == "cowrie.session.connect":
        db.execute_query("""
            INSERT INTO sessions (session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE src_ip=VALUES(src_ip), start_time=VALUES(start_time)
        """, (sid, e.get("src_ip"), e.get("src_port"), e.get("dst_port"), ts_str, None, None), fetch=None)

    elif eid == "cowrie.session.closed":
        db.execute_query("""
            INSERT INTO sessions (session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE end_time=VALUES(end_time), duration_ms=VALUES(duration_ms)
        """, (sid, None, None, None, None, ts_str, e.get("duration_ms")), fetch=None)

    elif eid in ("cowrie.login.success", "cowrie.login.failed"):
        db.execute_query("""
            INSERT INTO login_attempts (session_id, username, password, success, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, (sid, e.get("username"), e.get("password"), 1 if eid == "cowrie.login.success" else 0, ts_str), fetch=None)

    elif eid == "cowrie.command.input":
        db.execute_query("""
            INSERT INTO commands (session_id, input, timestamp)
            VALUES (%s, %s, %s)
        """, (sid, e.get("input"), ts_str), fetch=None)


def poll_logs_once():
    log_files = sorted(glob.glob(LOG_GLOB))
    if not log_files:
        log_files = sorted(glob.glob(LOCAL_LOG_GLOB))

    parsed_count = 0
    for path in log_files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str or line_str in PROCESSED_LINES:
                        continue
                    PROCESSED_LINES.add(line_str)
                    try:
                        event = json.loads(line_str)
                        process_event(event)
                        parsed_count += 1
                    except json.JSONDecodeError:
                        pass
        except Exception as err:
            pass

    return parsed_count


def start_realtime_log_watcher(interval_seconds=2):
    """Starts a background daemon thread that polls Cowrie JSON logs continuously every N seconds."""
    def watch_loop():
        print(f"[Realtime Watcher] Log watcher service active. Polling logs every {interval_seconds}s...")
        while True:
            try:
                new_events = poll_logs_once()
                if new_events > 0:
                    print(f"[Realtime Watcher] Ingested {new_events} new Cowrie security events into database.")
            except Exception as e:
                print(f"[Realtime Watcher Error] {e}")
            time.sleep(interval_seconds)

    thread = threading.Thread(target=watch_loop, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    count = poll_logs_once()
    print(f"Manual Log Poll Complete: {count} new events processed.")
