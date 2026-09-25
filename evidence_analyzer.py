import sys

sys.path.append("cowrie")

from database_test import get_latest_session, get_session_by_id

COMMAND_MEANINGS = {
    "whoami": "Identifies the current user account.",
    "id": "Displays the current user's UID, GID, and group memberships.",
    "uname -a": "Displays operating system and kernel information.",
    "ls -la": "Lists files and directories, including hidden files and permission information.",
    "cat /etc/passwd": "Reads Linux account information stored in /etc/passwd.",
    "exit": "Terminates the current session."
}


def analyze_session(data):
    if not data or not data.get("session"):
        return None

    session = data["session"]
    logins = data.get("logins", [])
    command_records = data.get("commands", [])

    successful_logins = sum(1 for login in logins if login.get("success") == 1)
    failed_logins = sum(1 for login in logins if login.get("success") == 0)

    commands = [command["input"] for command in command_records if command.get("input")]

    recon_command_list = ["whoami", "id", "uname -a", "ls -la", "cat /etc/passwd"]
    recon_commands = [cmd for cmd in commands if cmd in recon_command_list]

    command_analysis = []
    for command in commands:
        meaning = COMMAND_MEANINGS.get(command, "Standard interactive shell command.")
        command_analysis.append({
            "command": command,
            "meaning": meaning
        })

    authentication = "successful" if successful_logins > 0 else "unsuccessful"

    return {
        "session_id": session.get("session_id"),
        "source_ip": session.get("src_ip"),
        "destination_port": session.get("dst_port", 2222),
        "authentication": authentication,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "total_commands": len(commands),
        "commands": commands,
        "reconnaissance_commands": recon_commands,
        "reconnaissance_count": len(recon_commands),
        "command_analysis": command_analysis
    }


def get_evidence(session_id=None):
    if session_id:
        data = get_session_by_id(session_id)
    else:
        data = get_latest_session()

    if data is None:
        return None

    return analyze_session(data)


if __name__ == "__main__":
    evidence = get_evidence()
    if evidence:
        print("===== STRUCTURED EVIDENCE =====")
        print(evidence)
    else:
        print("No Cowrie sessions found.")
