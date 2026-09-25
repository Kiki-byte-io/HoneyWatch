from db_client import db

def get_latest_session():
    """Retrieves the latest session and its associated login attempts and commands."""
    session = db.execute_query(
        "SELECT session_id, src_ip, dst_port, start_time, end_time, duration_ms FROM sessions ORDER BY start_time DESC LIMIT 1",
        fetch="one"
    )
    if not session:
        return None

    sid = session["session_id"]
    return get_session_by_id(sid)


def get_session_by_id(session_id):
    """Retrieves session details by session_id."""
    session = db.execute_query(
        "SELECT session_id, src_ip, dst_port, start_time, end_time, duration_ms FROM sessions WHERE session_id = %s",
        params=(session_id,),
        fetch="one"
    )
    if not session:
        return None

    logins = db.execute_query(
        "SELECT session_id, username, password, success, timestamp FROM login_attempts WHERE session_id = %s ORDER BY timestamp",
        params=(session_id,),
        fetch="all"
    )
    commands = db.execute_query(
        "SELECT session_id, input, timestamp FROM commands WHERE session_id = %s ORDER BY timestamp",
        params=(session_id,),
        fetch="all"
    )

    return {
        "session": session,
        "logins": logins or [],
        "commands": commands or []
    }
