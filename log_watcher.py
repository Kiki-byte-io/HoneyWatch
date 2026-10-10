import os
import glob
import json
import logging
import time
import threading
from datetime import datetime
from db_client import db

LOG_GLOB = os.getenv(
    "COWRIE_LOG_GLOB",
    os.path.expanduser("~/cowrie-honeypot-capture/cowrie/var/log/cowrie/cowrie.json*")
)
LOCAL_LOG_GLOB = os.path.join(os.path.dirname(__file__), "cowrie*.json*")

# In-memory byte positions keyed by file identity, so renaming a rotated file
# does not make its already-read contents look like a new log.
FILE_OFFSETS = {}
logger = logging.getLogger(__name__)


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
        """, (sid, e.get("src_ip"), e.get("src_port"), e.get("dst_port"), ts_str, None, None), fetch=None, raise_on_error=True)

    elif eid == "cowrie.session.closed":
        db.execute_query("""
            INSERT INTO sessions (session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE end_time=VALUES(end_time), duration_ms=VALUES(duration_ms)
        """, (sid, None, None, None, None, ts_str, e.get("duration_ms")), fetch=None, raise_on_error=True)

    elif eid in ("cowrie.login.success", "cowrie.login.failed"):
        db.execute_query("""
            INSERT INTO login_attempts (session_id, username, password, success, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, (sid, e.get("username"), e.get("password"), 1 if eid == "cowrie.login.success" else 0, ts_str), fetch=None, raise_on_error=True)

    elif eid == "cowrie.command.input":
        db.execute_query("""
            INSERT INTO commands (session_id, input, timestamp)
            VALUES (%s, %s, %s)
        """, (sid, e.get("input"), ts_str), fetch=None, raise_on_error=True)


def poll_logs_once():
    log_files = sorted(glob.glob(LOG_GLOB))
    if not log_files:
        log_files = sorted(glob.glob(LOCAL_LOG_GLOB))

    processed_count = 0
    for path in log_files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                stat = os.fstat(f.fileno())
                identity = (stat.st_dev, stat.st_ino)
                state = FILE_OFFSETS.get(identity)

                # A new inode means rotation/replacement; a shorter file means
                # truncation. In either case, begin reading from byte zero.
                if state is None or stat.st_size < state[0]:
                    offset = 0
                    last_line = b""
                else:
                    offset = state[0]
                    last_line = state[1]

                    # Detect truncate-and-rewrite when the new contents have
                    # already grown past the old offset before this poll.
                    if last_line:
                        f.seek(offset - len(last_line))
                        if f.read(len(last_line)) != last_line:
                            offset = 0
                            last_line = b""

                # Save resets even when the only data after a reset is an
                # incomplete tail; otherwise an older offset could return.
                FILE_OFFSETS[identity] = (offset, last_line)

                f.seek(offset)
                while True:
                    line_start = f.tell()
                    raw_line = f.readline()
                    if not raw_line:
                        break
                    # JSONL records are complete only once newline-terminated.
                    # Keep an incomplete tail available for the next poll.
                    if not raw_line.endswith(b"\n"):
                        break

                    line_end = f.tell()
                    line = raw_line.strip()
                    if not line:
                        FILE_OFFSETS[identity] = (line_end, raw_line)
                        last_line = raw_line
                        continue

                    try:
                        event = json.loads(line.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError) as err:
                        logger.warning("Skipping malformed JSON in %s at byte %d: %s", path, line_start, err)
                        FILE_OFFSETS[identity] = (line_end, raw_line)
                        last_line = raw_line
                        continue

                    try:
                        process_event(event)
                    except Exception:
                        # Leave this record unconsumed so the next poll can retry it.
                        logger.exception("Could not process log record in %s at byte %d", path, line_start)
                        break

                    FILE_OFFSETS[identity] = (line_end, raw_line)
                    last_line = raw_line
                    processed_count += 1
        except OSError:
            logger.exception("Could not read Cowrie log file %s", path)

    return processed_count


def start_realtime_log_watcher(interval_seconds=2):
    """Starts a background daemon thread that polls Cowrie JSON logs continuously every N seconds."""
    def watch_loop():
        print(f"[Realtime Watcher] Log watcher service active. Polling logs every {interval_seconds}s...")
        while True:
            try:
                processed_events = poll_logs_once()
                if processed_events > 0:
                    print(f"[Realtime Watcher] Processed {processed_events} new Cowrie log events.")
            except Exception as e:
                print(f"[Realtime Watcher Error] {e}")
            time.sleep(interval_seconds)

    thread = threading.Thread(target=watch_loop, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    count = poll_logs_once()
    print(f"Manual Log Poll Complete: {count} new log events processed.")
