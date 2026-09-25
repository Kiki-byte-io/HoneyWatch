import requests
from evidence_analyzer import get_evidence

SUMMARY_CACHE = {}


def generate_summary(evidence=None):
    if evidence is None:
        evidence = get_evidence()

    if evidence is None:
        return {
            "summary": "No Cowrie sessions available yet for analysis.",
            "assessment": "No attack data available yet.",
            "authentication": "0 logins recorded.",
            "observed_commands": [],
            "recon_commands": []
        }

    sid = evidence.get("session_id", "default")
    if sid in SUMMARY_CACHE:
        return SUMMARY_CACHE[sid]

    authentication = (
        f"{evidence['successful_logins']} successful login(s) and "
        f"{evidence['failed_logins']} failed login(s) were recorded."
    )
    commands = evidence.get("commands", [])
    recon_commands = evidence.get("reconnaissance_commands", [])

    if evidence.get("failed_logins", 0) > 0:
        assessment = "The session included failed authentication attempts followed by observed command activity."
    else:
        assessment = (
            "The session involved successful authentication followed by system and account reconnaissance commands. "
            "No additional attack behavior is supported by the available evidence."
        )

    prompt = f"""
Write a short professional cybersecurity incident summary.

Use ONLY these verified facts:

Source IP: {evidence.get('source_ip')}
Destination port: {evidence.get('destination_port')}
Successful logins: {evidence.get('successful_logins')}
Failed logins: {evidence.get('failed_logins')}
Commands: {commands}
Reconnaissance commands: {recon_commands}

IMPORTANT:
Do not invent dates, times, usernames, commands, attack techniques, or attacker intent.
Do not claim brute force, credential theft, privilege escalation, malware, or persistence unless supported by facts.
Write one short paragraph describing the observed session.
"""

    ai_narrative = "AI narrative summary generated from verified evidence."
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "num_predict": 160
                }
            },
            timeout=3
        )
        if response.status_code == 200:
            ai_narrative = response.json().get("response", "").strip()
        else:
            ai_narrative = f"Observed session from {evidence.get('source_ip')} with {len(commands)} command(s) executed."
    except Exception:
        ai_narrative = f"Observed session from {evidence.get('source_ip')} on port {evidence.get('destination_port')}. Executed {len(commands)} command(s)."

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
