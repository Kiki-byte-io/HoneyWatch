import os
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from db_client import db
from bot_human_classifier import get_bot_assessment
from evidence_analyzer import get_evidence
from ai_mitigation import generate_mitigations
from ai_summarizer import generate_summary

COMMAND_MEANINGS = {
    "whoami": "Identifies current user account identity",
    "id": "Displays UID/GID and Linux group memberships",
    "uname -a": "Displays OS kernel version and hardware architecture",
    "ls -la": "Lists all directory files including hidden system files",
    "cat /etc/passwd": "Reads system user account registry file",
    "wget": "Downloads remote file payload over HTTP/HTTPS",
    "curl": "Transfers data from remote web server",
    "ps aux": "Lists active running processes on host",
    "ifconfig": "Lists network interface IP addresses",
    "history": "Inspects shell command execution history file",
    "exit": "Terminates current honeypot interactive session"
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
        LIMIT 8
    """, fetch="all") or []

    top_usernames = db.execute_query("""
        SELECT username, COUNT(*) AS count,
               SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS success_cnt,
               SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS fail_cnt
        FROM login_attempts
        WHERE username IS NOT NULL AND username != ''
        GROUP BY username
        ORDER BY count DESC
        LIMIT 8
    """, fetch="all") or []

    top_commands = db.execute_query("""
        SELECT input, COUNT(*) AS count
        FROM commands
        WHERE input IS NOT NULL AND input != ''
        GROUP BY input
        ORDER BY count DESC
        LIMIT 10
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
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=16,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155")
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=15,
        textColor=colors.HexColor("#1e293b")
    )

    elements = []

    # Title Block Header
    elements.append(Paragraph("🛡️ HONEYWATCH SECURITY REPORT", title_style))
    elements.append(Paragraph("Honeypot Monitoring & Threat Intelligence Analysis Report", subtitle_style))
    elements.append(Paragraph(
        f"<b>Report Timestamp:</b> {data['generated_at']} &nbsp;|&nbsp; <b>Telemetry Scope:</b> {range_filter.upper()} &nbsp;|&nbsp; <b>Database:</b> cowrie_logs",
        body_style
    ))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # SECTION 1: EXECUTIVE SUMMARY
    elements.append(Paragraph("1. EXECUTIVE SUMMARY", h2_style))
    summary_text = (
        f"This executive threat report summarizes security interaction telemetry collected by the <b>HoneyWatch</b> defensive system. "
        f"Across all monitored channels, the system captured <b>{data['tot_sessions']}</b> honeypot interactive sessions, "
        f"<b>{data['tot_logins']}</b> authentication attempts, and <b>{data['tot_commands']}</b> command execution payloads originating from "
        f"<b>{data['unique_ips']}</b> distinct external IP addresses.<br/><br/>"
        f"<b>Deterministically Verified Summary:</b><br/>"
        f"{data['summary_obj']['summary']}"
    )
    t_summary_box = Table([[Paragraph(summary_text, callout_style)]], colWidths=[532])
    t_summary_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(t_summary_box)
    elements.append(Spacer(1, 14))

    # SECTION 2: ATTACK OVERVIEW METRICS
    elements.append(Paragraph("2. ATTACK OVERVIEW TELEMETRY", h2_style))
    overview_data = [
        ["Telemetry Category", "Recorded Value", "Operational Status / Description"],
        ["Total Attack Events", str(data['tot_events']), "Aggregated security telemetry events"],
        ["Total Sessions", str(data['tot_sessions']), "Captured SSH/Telnet connections"],
        ["Unique Source IPs", str(data['unique_ips']), "Distinct external origin addresses"],
        ["Login Attempts", f"{data['tot_logins']} ({data['success_logins']} S / {data['failed_logins']} F)", "Auth trials (Successful vs Failed)"],
        ["Commands Captured", str(data['tot_commands']), "Shell execution payloads recorded"],
        ["Automation Threat Score", f"{data['bot_info']['automation_score']}/100", f"Assessment: {data['bot_info']['assessment']}"]
    ]
    t_overview = Table(overview_data, colWidths=[160, 140, 232])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_overview)
    elements.append(Spacer(1, 14))

    # SECTION 3: ATTACKER / SOURCE IP ANALYSIS
    elements.append(Paragraph("3. ATTACKER ORIGIN & SOURCE INFORMATION", h2_style))
    if data['top_ips']:
        ip_data = [["Source IP Address", "Captured Sessions", "Last Seen Timestamp"]]
        for ip in data['top_ips']:
            ip_data.append([ip['src_ip'], str(ip['session_count']), str(ip['last_seen'] or 'N/A')])
        t_ip = Table(ip_data, colWidths=[200, 140, 192])
        t_ip.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_ip)
    else:
        elements.append(Paragraph("<i>No source IP addresses recorded in the selected telemetry timeframe.</i>", body_style))

    elements.append(Spacer(1, 14))

    # SECTION 4: AUTHENTICATION ACTIVITY
    elements.append(Paragraph("4. AUTHENTICATION & TARGETED USERNAME ANALYSIS", h2_style))
    auth_intro = (
        f"A total of <b>{data['tot_logins']}</b> authentication trials were recorded. "
        f"Out of these, <b>{data['success_logins']}</b> logins succeeded while <b>{data['failed_logins']}</b> failed. "
        f"Targeted usernames indicate credential testing and dictionary enumeration. Passwords are redacted for security compliance."
    )
    elements.append(Paragraph(auth_intro, body_style))
    elements.append(Spacer(1, 8))

    if data['top_usernames']:
        u_data = [["Target Username", "Total Attempts", "Successful", "Failed"]]
        for u in data['top_usernames']:
            u_data.append([u['username'], str(u['count']), str(u['success_cnt'] or 0), str(u['fail_cnt'] or 0)])
        t_u = Table(u_data, colWidths=[180, 120, 116, 116])
        t_u.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_u)

    elements.append(Spacer(1, 14))

    # SECTION 5: COMMAND ACTIVITY & RECONNAISSANCE
    elements.append(KeepTogether([
        Paragraph("5. OBSERVED COMMAND PAYLOADS & RECONNAISSANCE FINDINGS", h2_style),
        Paragraph("The table below details actual shell command strings entered into the honeypot, alongside execution frequency and security purpose analysis:", body_style),
        Spacer(1, 8)
    ]))

    if data['top_commands']:
        cmd_data = [["Command String Payload", "Frequency", "Identified Purpose / Intent Meaning"]]
        for cmd in data['top_commands']:
            input_text = cmd['input']
            meaning = COMMAND_MEANINGS.get(input_text, "Interactive shell command execution")
            cmd_data.append([input_text, str(cmd['count']), meaning])
        t_cmd = Table(cmd_data, colWidths=[180, 80, 272])
        t_cmd.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_cmd)
    else:
        elements.append(Paragraph("<i>No command execution telemetry recorded in the selected period.</i>", body_style))

    elements.append(Spacer(1, 14))

    # SECTION 6: BOT / HUMAN BEHAVIORAL HEURISTIC ANALYSIS
    bot_info = data['bot_info']
    bot_content = [
        Paragraph("6. BOT / HUMAN BEHAVIORAL ANALYSIS", h2_style),
        Paragraph(f"<b>Assessment:</b> {bot_info['assessment']} &nbsp;|&nbsp; <b>Automation Score:</b> {bot_info['automation_score']}/100", body_style),
        Spacer(1, 6)
    ]
    feat = bot_info.get("behavioral_features", {})
    feat_table = [
        ["Behavioral Metric Feature", "Observed Value"],
        ["Sessions Observed", str(feat.get("sessions_observed", 0))],
        ["Commands Observed", str(feat.get("commands_observed", 0))],
        ["Average Command Interval (Gap)", f"{feat.get('average_gap', 0)} seconds"],
        ["Fast Command Transitions (< 1.5s)", str(feat.get("fast_commands", 0))],
        ["Repeated Command Sequences", str(feat.get("repeated_sequences", 0))],
        ["Repeated Source IPs", str(feat.get("repeated_ips", 0))],
        ["High-Frequency Burst Sessions", str(feat.get("high_frequency_sessions", 0))]
    ]
    t_feat = Table(feat_table, colWidths=[300, 232])
    t_feat.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    bot_content.append(t_feat)
    bot_content.append(Spacer(1, 8))

    ind_text = "<b>Observed Behavioral Indicators:</b><br/>"
    for ind in bot_info.get("indicators", []):
        ind_text += f"• {ind}<br/>"
    bot_content.append(Paragraph(ind_text, body_style))

    elements.append(KeepTogether(bot_content))
    elements.append(Spacer(1, 14))

    # SECTION 7: AI ATTACK SUMMARY
    ai_content = [
        Paragraph("7. AI ATTACK SUMMARY (ai_summarizer.py)", h2_style),
        Paragraph(data["summary_obj"]["summary"], body_style),
        Spacer(1, 14)
    ]
    elements.append(KeepTogether(ai_content))

    # SECTION 8: AI MITIGATION RECOMMENDATIONS
    mit_content = [
        Paragraph("8. AI MITIGATION RECOMMENDATIONS (ai_mitigation.py)", h2_style)
    ]
    if data['mitigations']:
        for i, m in enumerate(data['mitigations'], start=1):
            m_text = f"<b>{i}. Recommendation:</b> {m['recommendation']}<br/>&nbsp;&nbsp;&nbsp;&nbsp;<b>Rationale:</b> {m['reason']}"
            mit_content.append(Paragraph(m_text, body_style))
            mit_content.append(Spacer(1, 6))
    else:
        mit_content.append(Paragraph("<i>No specific mitigations required for current telemetry.</i>", body_style))

    elements.append(KeepTogether(mit_content))
    elements.append(Spacer(1, 14))

    # SECTION 9: FACTUAL CONCLUSION
    conc_text = (
        f"<b>9. FACTUAL CONCLUSION</b><br/><br/>"
        f"The HoneyWatch defensive platform successfully recorded and analyzed honeypot interaction across {data['tot_sessions']} "
        f"sessions, {data['tot_logins']} authentication attempts, and {data['tot_commands']} command execution payloads. "
        f"All intelligence findings, behavioral heuristic scores, and mitigation guidance strictly reflect factual telemetry stored in the database."
    )
    t_conc_box = Table([[Paragraph(conc_text, callout_style)]], colWidths=[532])
    t_conc_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(KeepTogether([t_conc_box]))

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94a3b8"), spaceAfter=10))
    elements.append(Paragraph("Official Threat Intelligence Document — Generated automatically by <b>HoneyWatch SOC Platform</b>.", ParagraphStyle('Foot', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#64748b"))))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


if __name__ == "__main__":
    pdf_bytes = generate_pdf_report("all")
    with open("HoneyWatch_Executive_Security_Report.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("Generated HoneyWatch_Executive_Security_Report.pdf successfully! Bytes:", len(pdf_bytes))
