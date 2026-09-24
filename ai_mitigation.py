from evidence_analyzer import get_evidence


# ---------------------------------------------------------
# Get verified evidence
# ---------------------------------------------------------

evidence = get_evidence()

if evidence is None:
    print("No Cowrie session found.")
    exit()


successful_logins = evidence["successful_logins"]
failed_logins = evidence["failed_logins"]

commands = evidence["commands"]
recon_commands = evidence["reconnaissance_commands"]


# ---------------------------------------------------------
# Deterministic mitigation engine
# ---------------------------------------------------------

recommendations = []


# 1. Successful authentication
if successful_logins > 0:

    recommendations.append({
        "recommendation":
            "Review SSH authentication controls and restrict SSH "
            "access to trusted hosts or networks.",
        "reason":
            f"{successful_logins} successful SSH login(s) were observed."
    })


# 2. Reconnaissance activity
if len(recon_commands) > 0:

    recommendations.append({
        "recommendation":
            "Monitor and alert on system and account reconnaissance "
            "commands executed during SSH sessions.",
        "reason":
            f"{len(recon_commands)} reconnaissance-related commands "
            "were observed."
    })


# 3. /etc/passwd access
if "cat /etc/passwd" in commands:

    recommendations.append({
        "recommendation":
            "Monitor access to sensitive account-information files "
            "such as /etc/passwd.",
        "reason":
            "The session read /etc/passwd, which contains Linux "
            "account information."
    })


# 4. Failed authentication
# Only recommend brute-force protections when evidence supports it.
if failed_logins >= 5:

    recommendations.append({
        "recommendation":
            "Review SSH rate-limiting and brute-force protection "
            "mechanisms.",
        "reason":
            f"{failed_logins} failed login attempts were observed."
    })


# ---------------------------------------------------------
# Display top 3 recommendations
# ---------------------------------------------------------

print("\n===== MITIGATION SUGGESTIONS =====\n")

for index, item in enumerate(recommendations[:3], start=1):

    print(f"{index}. Recommendation:")
    print(f"   {item['recommendation']}")

    print("   Reason:")
    print(f"   {item['reason']}")

    print()
