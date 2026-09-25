from evidence_analyzer import get_evidence


def generate_mitigations(evidence=None):
    if evidence is None:
        evidence = get_evidence()

    if evidence is None:
        return []

    successful_logins = evidence.get("successful_logins", 0)
    failed_logins = evidence.get("failed_logins", 0)
    commands = evidence.get("commands", [])
    recon_commands = evidence.get("reconnaissance_commands", [])

    recommendations = []

    # 1. Successful authentication
    if successful_logins > 0:
        recommendations.append({
            "recommendation": "Review SSH authentication controls and restrict SSH access to trusted hosts or networks.",
            "reason": f"{successful_logins} successful SSH login(s) were observed."
        })

    # 2. Reconnaissance activity
    if len(recon_commands) > 0:
        recommendations.append({
            "recommendation": "Monitor and alert on system and account reconnaissance commands executed during SSH sessions.",
            "reason": f"{len(recon_commands)} reconnaissance-related commands were observed."
        })

    # 3. /etc/passwd access
    if any("passwd" in cmd for cmd in commands):
        recommendations.append({
            "recommendation": "Monitor access to sensitive account-information files such as /etc/passwd.",
            "reason": "The session attempted to read account information files (/etc/passwd)."
        })

    # 4. Failed authentication
    if failed_logins >= 5:
        recommendations.append({
            "recommendation": "Review SSH rate-limiting and brute-force protection mechanisms.",
            "reason": f"{failed_logins} failed login attempts were observed."
        })

    return recommendations[:3]


if __name__ == "__main__":
    evidence = get_evidence()
    if evidence is None:
        print("No Cowrie session found.")
    else:
        recommendations = generate_mitigations(evidence)
        print("\n===== MITIGATION SUGGESTIONS =====\n")
        for index, item in enumerate(recommendations, start=1):
            print(f"{index}. Recommendation:\n   {item['recommendation']}\n   Reason:\n   {item['reason']}\n")
