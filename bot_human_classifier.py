from collections import Counter
from datetime import datetime
from db_client import db


def parse_dt(val):
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                pass
    return None


def get_bot_assessment():
    sessions = db.execute_query(
        "SELECT session_id, src_ip, start_time, end_time, duration_ms FROM sessions ORDER BY start_time",
        fetch="all"
    ) or []

    commands = db.execute_query(
        "SELECT session_id, input, timestamp FROM commands ORDER BY timestamp",
        fetch="all"
    ) or []

    if not sessions:
        return {
            "assessment": "Insufficient Evidence",
            "automation_score": 0,
            "indicators": ["No security sessions available yet."],
            "component_scores": {"timing": 0, "repetition": 0, "source": 0, "frequency": 0},
            "behavioral_features": {
                "sessions_observed": 0,
                "commands_observed": 0,
                "average_gap": 0.0,
                "fast_commands": 0,
                "repeated_sequences": 0,
                "repeated_ips": 0,
                "high_frequency_sessions": 0
            }
        }

    session_commands = {}
    for cmd in commands:
        sid = cmd["session_id"]
        session_commands.setdefault(sid, []).append(cmd)

    # FEATURE 1 - Command timing
    time_gaps = []
    for sid, cmd_list in session_commands.items():
        sorted_cmds = []
        for c in cmd_list:
            dt = parse_dt(c["timestamp"])
            if dt:
                sorted_cmds.append((dt, c))
        sorted_cmds.sort(key=lambda x: x[0])

        for i in range(1, len(sorted_cmds)):
            prev_dt = sorted_cmds[i - 1][0]
            curr_dt = sorted_cmds[i][0]
            gap = (curr_dt - prev_dt).total_seconds()
            if gap >= 0:
                time_gaps.append(gap)

    average_gap = (sum(time_gaps) / len(time_gaps)) if time_gaps else 0.0
    fast_commands = sum(1 for gap in time_gaps if gap < 3)

    if not time_gaps or fast_commands == 0:
        timing_score = 0
    else:
        fast_ratio = fast_commands / len(time_gaps)
        timing_score = round(min(25, fast_ratio * 25))

    # FEATURE 2 - Repeated command sequences
    sequence_counter = Counter()
    for sid, cmd_list in session_commands.items():
        seq = tuple(cmd["input"] for cmd in cmd_list if cmd.get("input"))
        if seq:
            sequence_counter[seq] += 1

    repeated_sequences = sum(1 for count in sequence_counter.values() if count > 1)
    if len(sequence_counter) == 0:
        repetition_score = 0
    else:
        repetition_score = round(min(25, (repeated_sequences / len(sequence_counter)) * 25))

    # FEATURE 3 - Repeated source IPs
    ip_counter = Counter(s["src_ip"] for s in sessions if s.get("src_ip"))
    repeated_ips = sum(1 for count in ip_counter.values() if count > 1)

    if len(sessions) <= 1:
        source_score = 0
    else:
        repeated_session_ratio = sum(count - 1 for count in ip_counter.values() if count > 1) / len(sessions)
        source_score = round(min(25, repeated_session_ratio * 25))

    # FEATURE 4 - High session frequency
    high_frequency_sessions = 0
    for ip in set(s["src_ip"] for s in sessions if s.get("src_ip")):
        ip_sessions = [s for s in sessions if s.get("src_ip") == ip]
        parsed_ip_sessions = []
        for s in ip_sessions:
            dt = parse_dt(s.get("start_time"))
            if dt:
                parsed_ip_sessions.append((dt, s))
        parsed_ip_sessions.sort(key=lambda x: x[0])

        for i in range(1, len(parsed_ip_sessions)):
            prev = parsed_ip_sessions[i - 1][0]
            curr = parsed_ip_sessions[i][0]
            gap = (curr - prev).total_seconds()
            if 0 <= gap < 60:
                high_frequency_sessions += 1

    if len(sessions) <= 1:
        frequency_score = 0
    else:
        frequency_ratio = high_frequency_sessions / max(1, len(sessions) - 1)
        frequency_score = round(min(25, frequency_ratio * 25))

    automation_score = timing_score + repetition_score + source_score + frequency_score

    enough_sessions = len(sessions) >= 3
    enough_commands = len(commands) >= 10

    if not enough_sessions or not enough_commands:
        assessment = "Insufficient Evidence"
    elif automation_score >= 60:
        assessment = "Likely Automated"
    elif automation_score >= 30:
        assessment = "Possibly Automated"
    else:
        assessment = "Insufficient Evidence"

    indicators = []
    if fast_commands > 0:
        indicators.append(f"{fast_commands} of {len(time_gaps)} command transitions occurred within 3 seconds.")
    if repeated_sequences > 0:
        indicators.append(f"{repeated_sequences} repeated command sequence(s) were observed.")
    if repeated_ips > 0:
        indicators.append("Multiple sessions originated from the same source IP.")
    if high_frequency_sessions > 0:
        indicators.append("Multiple sessions occurred within 60 seconds.")
    if not indicators:
        indicators.append("No automation indicators were observed.")

    return {
        "assessment": assessment,
        "automation_score": automation_score,
        "indicators": indicators,
        "component_scores": {
            "timing": timing_score,
            "repetition": repetition_score,
            "source": source_score,
            "frequency": frequency_score
        },
        "behavioral_features": {
            "sessions_observed": len(sessions),
            "commands_observed": len(commands),
            "average_gap": round(average_gap, 2),
            "fast_commands": fast_commands,
            "repeated_sequences": repeated_sequences,
            "repeated_ips": repeated_ips,
            "high_frequency_sessions": high_frequency_sessions
        }
    }


if __name__ == "__main__":
    res = get_bot_assessment()
    print("===== BOT / HUMAN ASSESSMENT =====")
    print("Assessment:", res["assessment"])
    print("Automation Score:", res["automation_score"])
    print("Indicators:", res["indicators"])
