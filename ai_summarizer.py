
import requests

from evidence_analyzer import get_evidence


evidence = get_evidence()

if evidence is None:
    print("No Cowrie session found.")
    exit()


# ---------------------------------------------------------
# VERIFIED FACTS
# ---------------------------------------------------------

authentication = (
    f"{evidence['successful_logins']} successful login(s) and "
    f"{evidence['failed_logins']} failed login(s) were recorded."
)

commands = evidence["commands"]

recon_commands = evidence["reconnaissance_commands"]


# ---------------------------------------------------------
# RULE-BASED OVERALL ASSESSMENT
# ---------------------------------------------------------

if evidence["failed_logins"] > 0:
    assessment = (
        "The session included failed authentication attempts "
        "followed by observed command activity."
    )
else:
    assessment = (
        "The session involved successful authentication followed "
        "by system and account reconnaissance commands. "
        "No additional attack behavior is supported by the "
        "available evidence."
    )


# ---------------------------------------------------------
# AI NARRATIVE
# ---------------------------------------------------------

prompt = f"""
Write a short professional cybersecurity incident summary.

Use ONLY these verified facts:

Source IP: {evidence['source_ip']}
Destination port: {evidence['destination_port']}
Successful logins: {evidence['successful_logins']}
Failed logins: {evidence['failed_logins']}
Commands: {commands}
Reconnaissance commands: {recon_commands}

IMPORTANT:
Do not invent dates, times, usernames, commands, attack techniques,
or attacker intent.

Do not claim:
- brute force
- credential theft
- privilege escalation
- malware
- persistence
- unauthorized access

Do not provide an overall security assessment.

Write one short paragraph describing the observed session.
"""


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
    timeout=120
)


# ---------------------------------------------------------
# DISPLAY REPORT
# ---------------------------------------------------------

print("HTTP status:", response.status_code)
print("\n===== AI ATTACK SUMMARY =====\n")

print("Authentication Activity:")
print(authentication)

print("\nObserved Activity:")
print(", ".join(commands))

print("\nReconnaissance Indicators:")
print(", ".join(recon_commands))

print("\nAI-Generated Summary:")

if response.status_code == 200:
    print(response.json()["response"].strip())
else:
    print("AI summary unavailable.")

print("\nOverall Assessment:")
print(assessment)
