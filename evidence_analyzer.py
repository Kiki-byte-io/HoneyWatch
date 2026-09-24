import sys

sys.path.append("cowrie")

from database_test import get_latest_session


# Known command meanings
COMMAND_MEANINGS = {
    "whoami": "Identifies the current user account.",
    "id": "Displays the current user's UID, GID, and group memberships.",
    "uname -a": "Displays operating system and kernel information.",
    "ls -la": "Lists files and directories, including hidden files and permission information.",
    "cat /etc/passwd": "Reads Linux account information stored in /etc/passwd.",
    "exit": "Terminates the current session."
}


def analyze_session(data):

    session = data["session"]
    logins = data["logins"]
    command_records = data["commands"]

    # Count successful and failed logins
    successful_logins = sum(
        1 for login in logins
        if login["success"] == 1
    )

    failed_logins = sum(
        1 for login in logins
        if login["success"] == 0
    )

    # Extract command strings
    commands = [
        command["input"]
        for command in command_records
    ]

    # Commands associated with reconnaissance
    recon_command_list = [
        "whoami",
        "id",
        "uname -a",
        "ls -la",
        "cat /etc/passwd"
    ]

    recon_commands = []

    for command in commands:
        if command in recon_command_list:
            recon_commands.append(command)

    # Create explanations for observed commands
    command_analysis = []

    for command in commands:
        if command in COMMAND_MEANINGS:
            command_analysis.append({
                "command": command,
                "meaning": COMMAND_MEANINGS[command]
            })

    # Determine authentication status
    if successful_logins > 0:
        authentication = "successful"
    else:
        authentication = "unsuccessful"

    # Build structured evidence
    evidence = {
        "session_id": session["session_id"],
        "source_ip": session["src_ip"],
        "destination_port": session["dst_port"],
        "authentication": authentication,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "total_commands": len(commands),
        "commands": commands,
        "reconnaissance_commands": recon_commands,
        "reconnaissance_count": len(recon_commands),
        "command_analysis": command_analysis
    }

    return evidence


def get_evidence():

    data = get_latest_session()

    if data is None:
        return None

    return analyze_session(data)


# Only print when this file is executed directly
if __name__ == "__main__":

    evidence = get_evidence()

    if evidence:
        print("===== STRUCTURED EVIDENCE =====")
        print(evidence)
    else:
        print("No Cowrie sessions found.")
