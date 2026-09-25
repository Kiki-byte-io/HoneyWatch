import os
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from db_client import db
from bot_human_classifier import get_bot_assessment
from evidence_analyzer import get_evidence
from ai_mitigation import generate_mitigations
from ai_summarizer import generate_summary

COMMAND_MEANINGS = {
    "whoami": "Identifies current user account",
    "id": "Displays UID/GID and group memberships",
    "uname -a": "Displays OS kernel and system architecture",
    "ls -la": "Lists all files including hidden system files",
    "cat /etc/passwd": "Reads system account registry file",
    "exit": "Terminates honeypot session"
}


def fetch_report_data(range_filter="all"):
    tot_sessions = db.execute_query("SELECT COUNT(*) AS count FROM sessions", fetch="one")["count"] or 0
    tot_logins = db.execute_query("SELECT COUNT(*) AS count FROM login_attempts", fetch="one")["count"] or 0
    tot_commands = db.execute_query("SELECT COUNT(*) AS count FROM commands", fetch="one")["count"] or 0
    unique_ips = db.execute_query("SELECT COUNT(DISTINCT src_ip) AS count FROM sessions WHERE src_ip IS NOT NULL", fetch="one")["count"] or 0

    success_logins = db.execute_query("SELECT COUNT(*) AS count FROM login_attempts WHERE success = 1", fetch="one")["count"] or 0
    failed_logins = db.execute_query("SELECT COUNT(*) AS count FROM login_attempts WHERE success = 0", fetch="one")["count"] or 0

    top_ips = db.execute_query("""
        SELECT src_ip, COUNT(*) AS session_count, MAX(start_time) AS last_seen
        FROM sessions
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY session_count DESC
        LIMIT 5
    """, fetch="all") or []

    top_usernames = db.execute_query("""
        SELECT username, COUNT(*) AS count
        FROM login_attempts
        WHERE username IS NOT NULL AND username != ''
        GROUP BY username
        ORDER BY count DESC
        LIMIT 5
    """, fetch="all") or []

    top_commands = db.execute_query("""
        SELECT input, COUNT(*) AS count
        FROM commands
        WHERE input IS NOT NULL AND input != ''
        GROUP BY input
        ORDER BY count DESC
        LIMIT 8
    """, fetch="all") or []

    evidence = get_evidence()
    summary_obj = generate_summary(evidence)
    mitigations = generate_mitigations(evidence)
    bot_info = get_bot_assessment()

    return {
        "range_filter": range_filter,
        "tot_sessions": tot_sessions,
        "tot_logins": tot_logins,
        "tot_commands": tot_commands,
        "tot_events": tot_sessions + tot_logins + tot_commands,
        "unique_ips": unique_ips,
        "success_logins": success_logins,
        "failed_logins": failed_logins,
        "top_ips": top_ips,
        "top_usernames": top_usernames,
        "top_commands": top_commands,
        "evidence": evidence,
        "summary_obj": summary_obj,
        "mitigations": mitigations,
        "bot_info": bot_info,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    }


def generate_pdf_report(range_filter="all"):
    data = fetch_report_data(range_filter)
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    elements = []

    # Header / Title Block
    elements.append(Paragraph("🛡️ HONEYWATCH", title_style))
    elements.append(Paragraph("Honeypot Monitoring & Attack Analysis Report", subtitle_style))
    elements.append(Paragraph(f"<b>Report Generated:</b> {data['generated_at']} &nbsp;|&nbsp; <b>Telemetry Range:</b> {range_filter.upper()}", body_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # SECTION 1: EXECUTIVE SUMMARY
    elements.append(Paragraph("1. EXECUTIVE SUMMARY", h2_style))
    elements.append(Paragraph(data["summary_obj"]["summary"], body_style))
    elements.append(Spacer(1, 10))

    # SECTION 2: ATTACK OVERVIEW
    elements.append(Paragraph("2. ATTACK OVERVIEW", h2_style))
    overview_data = [
        ["Metric Name", "Recorded Value", "System Status"],
        ["Total Attack Events", str(data['tot_events']), "Aggregated security telemetry"],
        ["Total Sessions", str(data['tot_sessions']), "Captured honeypot connections"],
        ["Unique Source IPs", str(data['unique_ips']), "Distinct external origin addresses"],
        ["Login Attempts", f"{data['tot_logins']} ({data['success_logins']} S / {data['failed_logins']} F)", "Auth trials (Success / Failed)"],
        ["Commands Captured", str(data['tot_commands']), "Shell execution payloads recorded"]
    ]
    t_overview = Table(overview_data, colWidths=[160, 140, 240])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t_overview)
    elements.append(Spacer(1, 10))

    # SECTION 3: ATTACKER / SOURCE INFORMATION
    elements.append(Paragraph("3. ATTACKER / SOURCE INFORMATION", h2_style))
    if data['top_ips']:
        ip_data = [["Source IP Address", "Session Count", "Last Active Timestamp"]]
        for ip in data['top_ips']:
            ip_data.append([ip['src_ip'], str(ip['session_count']), str(ip['last_seen'] or 'N/A')])
        t_ip = Table(ip_data, colWidths=[200, 140, 200])
        t_ip.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_ip)
    else:
        elements.append(Paragraph("<i>No source IP addresses recorded in the selected period.</i>", body_style))

    elements.append(Spacer(1, 10))

    # SECTION 4: AUTHENTICATION ACTIVITY
    elements.append(Paragraph("4. AUTHENTICATION ACTIVITY", h2_style))
    auth_text = (
        f"A total of <b>{data['tot_logins']}</b> authentication trials were recorded, consisting of "
        f"<b>{data['success_logins']}</b> successful logins and <b>{data['failed_logins']}</b> failed login attempts. "
        "Passwords are automatically redacted to uphold security controls."
    )
    elements.append(Paragraph(auth_text, body_style))
    elements.append(Spacer(1, 10))

    # SECTION 5: COMMAND ACTIVITY
    elements.append(Paragraph("5. COMMAND ACTIVITY & RECONNAISSANCE FINDINGS", h2_style))
    if data['top_commands']:
        cmd_data = [["Command Payload String", "Execution Frequency", "Identified Purpose / Intent Meaning"]]
        for cmd in data['top_commands']:
            input_text = cmd['input']
            meaning = COMMAND_MEANINGS.get(input_text, "Interactive shell command")
            cmd_data.append([input_text, str(cmd['count']), meaning])
        t_cmd = Table(cmd_data, colWidths=[180, 100, 260])
        t_cmd.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_cmd)
    else:
        elements.append(Paragraph("<i>No command execution data recorded in the selected period.</i>", body_style))

    elements.append(Spacer(1, 10))

    # SECTION 6: BOT / HUMAN BEHAVIORAL ANALYSIS
    elements.append(Paragraph("6. BOT / HUMAN BEHAVIORAL ANALYSIS", h2_style))
    bot_info = data['bot_info']
    bot_text = (
        f"<b>Assessment:</b> {bot_info['assessment']}<br/>"
        f"<b>Automation Threat Score:</b> {bot_info['automation_score']}/100<br/>"
        f"<b>Behavioral Metrics:</b> Sessions observed: {bot_info['behavioral_features']['sessions_observed']} | "
        f"Commands observed: {bot_info['behavioral_features']['commands_observed']} | "
        f"Average command interval: {bot_info['behavioral_features']['average_gap']}s<br/>"
        f"<b>Observed Indicators:</b><br/>"
    )
    for ind in bot_info.get("indicators", []):
        bot_text += f"• {ind}<br/>"

    elements.append(Paragraph(bot_text, body_style))
    elements.append(Spacer(1, 10))

    # SECTION 7: AI ATTACK SUMMARY
    elements.append(Paragraph("7. AI ATTACK SUMMARY", h2_style))
    elements.append(Paragraph(data["summary_obj"]["summary"], body_style))
    elements.append(Spacer(1, 10))

    # SECTION 8: AI MITIGATION RECOMMENDATIONS
    elements.append(Paragraph("8. AI MITIGATION RECOMMENDATIONS", h2_style))
    if data['mitigations']:
        for i, m in enumerate(data['mitigations'], start=1):
            m_text = f"<b>{i}. Recommendation:</b> {m['recommendation']}<br/>&nbsp;&nbsp;&nbsp;&nbsp;<b>Reason:</b> {m['reason']}"
            elements.append(Paragraph(m_text, body_style))
            elements.append(Spacer(1, 4))
    else:
        elements.append(Paragraph("<i>No specific mitigations generated for current evidence.</i>", body_style))

    elements.append(Spacer(1, 10))

    # SECTION 9: CONCLUSION
    elements.append(Paragraph("9. FACTUAL CONCLUSION", h2_style))
    conclusion_text = (
        f"The HoneyWatch defensive platform successfully monitored honeypot interaction across {data['tot_sessions']} "
        f"sessions and recorded {data['tot_commands']} command execution payloads. Security findings and automation "
        f"scores reflect factual telemetry stored in MySQL."
    )
    elements.append(Paragraph(conclusion_text, body_style))

    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    elements.append(Paragraph("Report generated automatically by <b>HoneyWatch Defensive Platform</b>.", ParagraphStyle('Foot', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#64748b"))))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


if __name__ == "__main__":
    pdf_bytes = generate_pdf_report("all")
    with open("HoneyWatch_Executive_Security_Report.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("Generated HoneyWatch_Executive_Security_Report.pdf successfully! Bytes:", len(pdf_bytes))
