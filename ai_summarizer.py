import requests
from evidence_analyzer import get_evidence

SUMMARY_CACHE = {}


def generate_summary(evidence=None):
    if evidence is None:
        evidence = get_evidence()

    if evidence is None:
        return {
            "summary": "No Cowrie honeypot sessions available yet for AI threat analysis.",
            "assessment": "No attack data available yet.",
            "authentication": "0 logins recorded.",
            "observed_commands": [],
            "recon_commands": []
        }

    sid = evidence.get("session_id", "default")
    if sid in SUMMARY_CACHE:
        return SUMMARY_CACHE[sid]

    authentication = (
        f"{evidence.get('successful_logins', 0)} successful login(s) and "
        f"{evidence.get('failed_logins', 0)} failed login(s) were recorded."
    )
    commands = evidence.get("commands", [])
    recon_commands = evidence.get("reconnaissance_commands", [])

    if evidence.get("failed_logins", 0) > 0 and evidence.get("successful_logins", 0) == 0:
        assessment = "The session involved unauthenticated credential trial attempts."
    elif evidence.get("failed_logins", 0) > 0 and evidence.get("successful_logins", 0) > 0:
        assessment = "The session included initial failed authentication attempts followed by a successful login and interactive command execution."
    else:
        assessment = (
            "The session involved successful authentication followed by system and account reconnaissance commands. "
            "No additional attack behavior is supported by the available evidence."
        )

    cmd_formatted = ", ".join([f"'{c}'" for c in commands]) if commands else "None"
    recon_formatted = ", ".join([f"'{c}'" for c in recon_commands]) if recon_commands else "None"

    deterministic_summary = (
        f"Targeting port {evidence.get('destination_port', 2222)}, an interactive session was established from source IP {evidence.get('source_ip', 'Unknown')} (Session ID: {sid}). "
        f"Authentication telemetry recorded {evidence.get('successful_logins', 0)} successful login(s) and {evidence.get('failed_logins', 0)} failed attempt(s). "
        f"During interaction, {len(commands)} shell command payload(s) were executed: [{cmd_formatted}]. "
        f"Reconnaissance indicators detected {len(recon_commands)} system inspection command(s): [{recon_formatted}]. "
        f"{assessment}"
    )

    prompt = f"""
Write a professional cybersecurity incident summary paragraph based strictly on verified facts.

Facts:
Source IP: {evidence.get('source_ip')}
Destination port: {evidence.get('destination_port')}
Successful logins: {evidence.get('successful_logins')}
Failed logins: {evidence.get('failed_logins')}
Commands executed: {commands}
Reconnaissance commands: {recon_commands}
Assessment: {assessment}

Do not invent unauthorized details, dates, or malicious intentions beyond these facts.
"""

    ai_narrative = deterministic_summary
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "num_predict": 180
                }
            },
            timeout=3
        )
        if response.status_code == 200:
            llm_res = response.json().get("response", "").strip()
            if llm_res:
                ai_narrative = llm_res
    except Exception:
        ai_narrative = deterministic_summary

    result = {
        "summary": ai_narrative,
        "assessment": assessment,
        "authentication": authentication,
        "observed_commands": commands,
        "recon_commands": recon_commands
    }

    SUMMARY_CACHE[sid] = result
    return result


if __name__ == "__main__":
    res = generate_summary()
    print("===== AI ATTACK SUMMARY =====")
    print("Summary:", res["summary"])
    print("Assessment:", res["assessment"])
