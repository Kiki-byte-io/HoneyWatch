import os
import mysql.connector
from collections import Counter


# ---------------------------------------------------------
# Database connection
# ---------------------------------------------------------

db = mysql.connector.connect(
    host="localhost",
    user="cowrie_app",
    password=os.getenv("COWRIE_DB_PASSWORD"),
    database="cowrie_logs"
)

cursor = db.cursor(dictionary=True)


# ---------------------------------------------------------
# Retrieve sessions
# ---------------------------------------------------------

cursor.execute("""
    SELECT session_id, src_ip, start_time, end_time, duration_ms
    FROM sessions
    ORDER BY start_time
""")

sessions = cursor.fetchall()


# ---------------------------------------------------------
# Retrieve commands
# ---------------------------------------------------------

cursor.execute("""
    SELECT session_id, input, timestamp
    FROM commands
    ORDER BY timestamp
""")

commands = cursor.fetchall()

cursor.close()
db.close()


if not sessions:

    print("No sessions found.")
    exit()


# ---------------------------------------------------------
# Organize commands by session
# ---------------------------------------------------------

session_commands = {}

for command in commands:

    session_id = command["session_id"]

    session_commands.setdefault(session_id, []).append(command)


# ---------------------------------------------------------
# FEATURE 1 — Command timing
# ---------------------------------------------------------

time_gaps = []

for session_id, cmd_list in session_commands.items():

    cmd_list.sort(key=lambda x: x["timestamp"])

    for i in range(1, len(cmd_list)):

        previous = cmd_list[i - 1]["timestamp"]
        current = cmd_list[i]["timestamp"]

        gap = (current - previous).total_seconds()

        time_gaps.append(gap)


average_gap = (
    sum(time_gaps) / len(time_gaps)
    if time_gaps
    else 0
)


fast_commands = sum(
    1 for gap in time_gaps
    if gap < 3
)


# ---------------------------------------------------------
# TIMING SCORE — 0 to 25
# ---------------------------------------------------------

if not time_gaps:

    timing_score = 0

elif fast_commands == 0:

    timing_score = 0

else:

    fast_ratio = fast_commands / len(time_gaps)

    timing_score = round(
        min(25, fast_ratio * 25)
    )


# ---------------------------------------------------------
# FEATURE 2 — Repeated command sequences
# ---------------------------------------------------------

sequence_counter = Counter()

for session_id, cmd_list in session_commands.items():

    sequence = tuple(
        command["input"]
        for command in sorted(
            cmd_list,
            key=lambda x: x["timestamp"]
        )
    )

    if sequence:

        sequence_counter[sequence] += 1


repeated_sequences = sum(
    1
    for count in sequence_counter.values()
    if count > 1
)


# ---------------------------------------------------------
# REPETITION SCORE — 0 to 25
# ---------------------------------------------------------

if len(sequence_counter) == 0:

    repetition_score = 0

else:

    repetition_score = round(
        min(
            25,
            (repeated_sequences / len(sequence_counter)) * 25
        )
    )


# ---------------------------------------------------------
# FEATURE 3 — Repeated source IPs
# ---------------------------------------------------------

ip_counter = Counter(
    session["src_ip"]
    for session in sessions
)


repeated_ips = sum(
    1
    for count in ip_counter.values()
    if count > 1
)


# ---------------------------------------------------------
# SOURCE SCORE — 0 to 25
# ---------------------------------------------------------

if len(sessions) <= 1:

    source_score = 0

else:

    repeated_session_ratio = (
        sum(
            count - 1
            for count in ip_counter.values()
            if count > 1
        )
        / len(sessions)
    )

    source_score = round(
        min(25, repeated_session_ratio * 25)
    )


# ---------------------------------------------------------
# FEATURE 4 — High session frequency
# ---------------------------------------------------------

high_frequency_sessions = 0


for ip in set(
    session["src_ip"]
    for session in sessions
):

    ip_sessions = [
        session
        for session in sessions
        if session["src_ip"] == ip
    ]

    ip_sessions.sort(
        key=lambda x: x["start_time"]
    )

    for i in range(1, len(ip_sessions)):

        previous = ip_sessions[i - 1]["start_time"]
        current = ip_sessions[i]["start_time"]

        gap = (
            current - previous
        ).total_seconds()

        if gap < 60:

            high_frequency_sessions += 1


# ---------------------------------------------------------
# FREQUENCY SCORE — 0 to 25
# ---------------------------------------------------------

if len(sessions) <= 1:

    frequency_score = 0

else:

    frequency_ratio = (
        high_frequency_sessions
        / max(1, len(sessions) - 1)
    )

    frequency_score = round(
        min(25, frequency_ratio * 25)
    )


# ---------------------------------------------------------
# TOTAL AUTOMATION SCORE
# ---------------------------------------------------------

automation_score = (
    timing_score
    + repetition_score
    + source_score
    + frequency_score
)


# ---------------------------------------------------------
# Evidence sufficiency
# ---------------------------------------------------------

enough_sessions = len(sessions) >= 3
enough_commands = len(commands) >= 10


# ---------------------------------------------------------
# Assessment
# ---------------------------------------------------------

if not enough_sessions or not enough_commands:

    assessment = "Insufficient Evidence"

elif automation_score >= 60:

    assessment = "Likely Automated"

elif automation_score >= 30:

    assessment = "Possibly Automated"

else:

    assessment = "Insufficient Evidence"


# ---------------------------------------------------------
# Indicators
# ---------------------------------------------------------

indicators = []


if fast_commands > 0:

    indicators.append(
        f"{fast_commands} of {len(time_gaps)} "
        "command transitions occurred within 3 seconds."
    )


if repeated_sequences > 0:

    indicators.append(
        f"{repeated_sequences} repeated command sequence(s) "
        "were observed."
    )


if repeated_ips > 0:

    indicators.append(
        "Multiple sessions originated from the same source IP."
    )


if high_frequency_sessions > 0:

    indicators.append(
        "Multiple sessions occurred within 60 seconds."
    )


if not indicators:

    indicators.append(
        "No automation indicators were observed."
    )

elif (
    len(indicators) == 1
    and fast_commands > 0
    and repeated_sequences == 0
    and repeated_ips == 0
    and high_frequency_sessions == 0
):

    indicators.append(
        "The timing indicator alone is insufficient to "
        "indicate automated activity."
    )

# ---------------------------------------------------------
# Display
# ---------------------------------------------------------

print("\n===== BOT / HUMAN ASSESSMENT =====\n")

print(f"Assessment: {assessment}")

print(
    f"Automation Score: "
    f"{automation_score}/100"
)


print("\nBehavioral Features:")

print(
    f"Sessions observed: "
    f"{len(sessions)}"
)

print(
    f"Commands observed: "
    f"{len(commands)}"
)

print(
    f"Average command interval: "
    f"{average_gap:.2f} seconds"
)

print(
    f"Fast command transitions (<3s): "
    f"{fast_commands}"
)

print(
    f"Repeated command sequences: "
    f"{repeated_sequences}"
)

print(
    f"Repeated source IPs: "
    f"{repeated_ips}"
)

print(
    f"High-frequency sessions (<60s): "
    f"{high_frequency_sessions}"
)


print("\nComponent Scores:")

print(
    f"Command timing: "
    f"{timing_score}/25"
)

print(
    f"Command repetition: "
    f"{repetition_score}/25"
)

print(
    f"Repeated sources: "
    f"{source_score}/25"
)

print(
    f"Session frequency: "
    f"{frequency_score}/25"
)


print("\nIndicators:")

for indicator in indicators:

    print(f"- {indicator}")


print("\nInterpretation:")

if assessment == "Likely Automated":

    print(
        "Multiple behavioral indicators are consistent "
        "with automated activity."
    )

elif assessment == "Possibly Automated":

    print(
        "Some behavioral indicators are consistent with "
        "automated activity, but the evidence is not conclusive."
    )

else:

    print(
        "The available session history is insufficient "
        "to reliably distinguish automated activity from "
        "human-operated activity."
    )
