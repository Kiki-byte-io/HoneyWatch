import os
import io
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

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


def get_cutoff_str(range_filter):
    now = datetime.now()
    if range_filter == "24h":
        cutoff = now - timedelta(days=1)
    elif range_filter == "7d":
        cutoff = now - timedelta(days=7)
    elif range_filter == "30d":
        cutoff = now - timedelta(days=30)
    else:
        return None
    return cutoff.strftime("%Y-%m-%d %H:%M:%S")


def fetch_report_data(range_filter="all"):
    cutoff = get_cutoff_str(range_filter)

    s_where = " WHERE start_time >= %s" if cutoff else ""
    l_where = " WHERE timestamp >= %s" if cutoff else ""
    c_where = " WHERE timestamp >= %s" if cutoff else ""

    params = (cutoff,) if cutoff else None

    tot_sessions = db.execute_query(f"SELECT COUNT(*) AS count FROM sessions{s_where}", params=params, fetch="one")["count"] or 0
    tot_logins = db.execute_query(f"SELECT COUNT(*) AS count FROM login_attempts{l_where}", params=params, fetch="one")["count"] or 0
    tot_commands = db.execute_query(f"SELECT COUNT(*) AS count FROM commands{c_where}", params=params, fetch="one")["count"] or 0

    unique_ip_query = "SELECT COUNT(DISTINCT src_ip) AS count FROM sessions WHERE src_ip IS NOT NULL"
    if cutoff:
        unique_ip_query += " AND start_time >= %s"
    unique_ips = db.execute_query(unique_ip_query, params=params, fetch="one")["count"] or 0

    succ_query = "SELECT COUNT(*) AS count FROM login_attempts WHERE success = 1"
    if cutoff:
        succ_query += " AND timestamp >= %s"
    success_logins = db.execute_query(succ_query, params=params, fetch="one")["count"] or 0

    fail_query = "SELECT COUNT(*) AS count FROM login_attempts WHERE success = 0"
    if cutoff:
        fail_query += " AND timestamp >= %s"
    failed_logins = db.execute_query(fail_query, params=params, fetch="one")["count"] or 0

    top_ips_query = f"""
        SELECT src_ip, COUNT(*) AS session_count, MAX(start_time) AS last_seen
        FROM sessions
        WHERE src_ip IS NOT NULL AND src_ip != ''
        {"AND start_time >= %s" if cutoff else ""}
        GROUP BY src_ip
        ORDER BY session_count DESC
        LIMIT 8
    """
    top_ips = db.execute_query(top_ips_query, params=params, fetch="all") or []

    recent_sessions_query = f"""
        SELECT s.session_id, s.src_ip, s.dst_port, s.start_time, s.duration_ms,
               (SELECT COUNT(*) FROM login_attempts WHERE session_id = s.session_id) AS login_cnt,
               (SELECT COUNT(*) FROM commands WHERE session_id = s.session_id) AS cmd_cnt
        FROM sessions s
        {"WHERE s.start_time >= %s" if cutoff else ""}
        ORDER BY s.start_time DESC
        LIMIT 8
    """
    recent_sessions = db.execute_query(recent_sessions_query, params=params, fetch="all") or []

    top_usernames_query = f"""
        SELECT username, COUNT(*) AS count,
               SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS success_cnt,
               SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS fail_cnt
        FROM login_attempts
        WHERE username IS NOT NULL AND username != ''
        {"AND timestamp >= %s" if cutoff else ""}
        GROUP BY username
        ORDER BY count DESC
        LIMIT 8
    """
    top_usernames = db.execute_query(top_usernames_query, params=params, fetch="all") or []

    top_commands_query = f"""
        SELECT input, COUNT(*) AS count
        FROM commands
        WHERE input IS NOT NULL AND input != ''
        {"AND timestamp >= %s" if cutoff else ""}
        GROUP BY input
        ORDER BY count DESC
        LIMIT 10
    """
    top_commands = db.execute_query(top_commands_query, params=params, fetch="all") or []

    evidence = get_evidence()
    summary_obj = generate_summary(evidence)
    mitigations = generate_mitigations(evidence)
    bot_info = get_bot_assessment()

    range_labels = {
        "24h": "Last 24 Hours",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
        "all": "All Available Telemetry Data"
    }

    return {
        "range_filter": range_filter,
        "range_label": range_labels.get(range_filter, "All Available Telemetry Data"),
        "tot_sessions": tot_sessions,
        "tot_logins": tot_logins,
        "tot_commands": tot_commands,
        "tot_events": tot_sessions + tot_logins + tot_commands,
        "unique_ips": unique_ips,
        "success_logins": success_logins,
        "failed_logins": failed_logins,
        "top_ips": top_ips,
        "recent_sessions": recent_sessions,
        "top_usernames": top_usernames,
        "top_commands": top_commands,
        "evidence": evidence,
        "summary_obj": summary_obj,
        "mitigations": mitigations,
        "bot_info": bot_info,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "report_date_str": datetime.now().strftime("%Y-%m-%d")
    }


def build_attack_chart(tot_sessions, tot_logins, tot_commands):
    drawing = Drawing(532, 140)
    chart = VerticalBarChart()
    chart.x = 40
    chart.y = 20
    chart.height = 95
    chart.width = 460
    chart.data = [[tot_sessions, tot_logins, tot_commands]]
    chart.categoryAxis.categoryNames = ['Total Sessions', 'Login Attempts', 'Commands Captured']
    chart.categoryAxis.labels.fontSize = 9
    chart.categoryAxis.labels.fontName = 'Helvetica-Bold'
    chart.categoryAxis.labels.fillColor = colors.HexColor("#0f172a")

    max_val = max(1, max(tot_sessions, tot_logins, tot_commands))
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max_val + max(1, int(max_val * 0.15))
    chart.valueAxis.valueStep = max(1, chart.valueAxis.valueMax // 4)
    chart.valueAxis.labels.fontSize = 8
    chart.bars[0].fillColor = colors.HexColor("#0284c7")

    drawing.add(chart)
    return drawing


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
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=2
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=12
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
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155")
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1e293b")
    )

    elements = []

    # Title & Header Block
    elements.append(Paragraph("🛡️ HONEYWATCH", title_style))
    elements.append(Paragraph("Honeypot-Based Attack Monitoring and Threat Intelligence System", subtitle_style))
    elements.append(Paragraph("<b>EXECUTIVE SECURITY REPORT</b>", ParagraphStyle('H1Sub', parent=subtitle_style, fontSize=13, textColor=colors.HexColor("#0f172a"))))
    elements.append(Paragraph(
        f"<b>Report Generated:</b> {data['generated_at']} &nbsp;|&nbsp; <b>Telemetry Scope:</b> {data['range_label']}",
        body_style
    ))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # SECTION 1: KEY METRICS
    elements.append(Paragraph("1. KEY METRICS", h2_style))
    metrics_data = [
        ["Total Events", "Unique Source IPs", "Total Sessions", "Login Attempts", "Commands Captured"],
        [str(data['tot_events']), str(data['unique_ips']), str(data['tot_sessions']), str(data['tot_logins']), str(data['tot_commands'])]
    ]
    t_metrics = Table(metrics_data, colWidths=[106, 106, 106, 106, 108])
    t_metrics.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8.5),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, 1), 13),
        ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor("#0284c7")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_metrics)
    elements.append(Spacer(1, 12))

    # SECTION 2: ATTACK ACTIVITY
    elements.append(Paragraph("2. ATTACK ACTIVITY CHART", h2_style))
    elements.append(build_attack_chart(data['tot_sessions'], data['tot_logins'], data['tot_commands']))
    elements.append(Spacer(1, 12))

    # SECTION 3: SOURCE IP ANALYSIS
    elements.append(Paragraph("3. SOURCE IP ANALYSIS", h2_style))
    if data['top_ips']:
        ip_table_data = [["Source IP Address", "Session Count", "Last Active Timestamp"]]
        for ip in data['top_ips']:
            ip_table_data.append([ip['src_ip'], str(ip['session_count']), str(ip['last_seen'] or 'N/A')])
        t_ip = Table(ip_table_data, colWidths=[200, 132, 200])
        t_ip.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_ip)
    else:
        elements.append(Paragraph("<i>No source IP activity recorded in the selected date range.</i>", body_style))
    elements.append(Spacer(1, 12))

    # SECTION 4: SESSION ANALYSIS
    elements.append(Paragraph("4. SESSION ANALYSIS", h2_style))
    if data['recent_sessions']:
        s_table_data = [["Session ID", "Source IP", "Port", "Start Time", "Logins", "Commands"]]
        for s in data['recent_sessions']:
            s_table_data.append([
                s['session_id'],
                s['src_ip'] or 'N/A',
                str(s['dst_port'] or 2222),
                str(s['start_time'] or 'N/A'),
                str(s['login_cnt']),
                str(s['cmd_cnt'])
            ])
        t_s = Table(s_table_data, colWidths=[110, 110, 50, 162, 50, 50])
        t_s.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_s)
    else:
        elements.append(Paragraph("<i>No session records available in the selected date range.</i>", body_style))
    elements.append(Spacer(1, 12))

    # SECTION 5: AUTHENTICATION ACTIVITY
    elements.append(Paragraph("5. AUTHENTICATION ACTIVITY", h2_style))
    auth_intro = (
        f"Authentication telemetry recorded <b>{data['tot_logins']}</b> total login trials "
        f"(<b>{data['success_logins']}</b> successful / <b>{data['failed_logins']}</b> failed). "
        "Captured passwords are redacted to uphold security rules."
    )
    elements.append(Paragraph(auth_intro, body_style))
    elements.append(Spacer(1, 6))

    if data['top_usernames']:
        u_table = [["Target Username", "Total Attempts", "Successful", "Failed"]]
        for u in data['top_usernames']:
            u_table.append([u['username'], str(u['count']), str(u['success_cnt'] or 0), str(u['fail_cnt'] or 0)])
        t_u = Table(u_table, colWidths=[180, 120, 116, 116])
        t_u.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_u)
    elements.append(Spacer(1, 12))

    # SECTION 6: COMMAND ANALYSIS
    elements.append(KeepTogether([
        Paragraph("6. COMMAND ANALYSIS", h2_style),
        Paragraph("Actual shell commands executed on the honeypot alongside security intent meanings:", body_style),
        Spacer(1, 6)
    ]))
    if data['top_commands']:
        cmd_table = [["Command Payload String", "Frequency", "Identified Purpose / Intent Meaning"]]
        for cmd in data['top_commands']:
            input_text = cmd['input']
            meaning = COMMAND_MEANINGS.get(input_text, "Interactive shell command execution")
            cmd_table.append([input_text, str(cmd['count']), meaning])
        t_cmd = Table(cmd_table, colWidths=[180, 80, 272])
        t_cmd.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_cmd)
    else:
        elements.append(Paragraph("<i>No command executions recorded in the selected period.</i>", body_style))
    elements.append(Spacer(1, 12))

    # SECTION 7: BOT / HUMAN BEHAVIORAL ANALYSIS
    bot_info = data['bot_info']
    bot_elements = [
        Paragraph("7. BOT / HUMAN BEHAVIORAL ANALYSIS", h2_style),
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
        ('FONTSIZE', (0, 0), (-1, -1), 8.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
    ]))
    bot_elements.append(t_feat)
    bot_elements.append(Spacer(1, 6))

    ind_text = "<b>Observed Behavioral Indicators:</b><br/>"
    for ind in bot_info.get("indicators", []):
        ind_text += f"• {ind}<br/>"
    bot_elements.append(Paragraph(ind_text, body_style))

    elements.append(KeepTogether(bot_elements))
    elements.append(Spacer(1, 12))

    # SECTION 8: AI ATTACK SUMMARY
    ai_elements = [
        Paragraph("8. AI ATTACK SUMMARY (ai_summarizer.py)", h2_style),
        Paragraph(data["summary_obj"]["summary"], body_style),
        Spacer(1, 12)
    ]
    elements.append(KeepTogether(ai_elements))

    # SECTION 9: AI MITIGATION RECOMMENDATIONS
    mit_elements = [
        Paragraph("9. AI MITIGATION RECOMMENDATIONS (ai_mitigation.py)", h2_style)
    ]
    if data['mitigations']:
        for i, m in enumerate(data['mitigations'], start=1):
            m_text = f"<b>{i}. Recommendation:</b> {m['recommendation']}<br/>&nbsp;&nbsp;&nbsp;&nbsp;<b>Rationale:</b> {m['reason']}"
            mit_elements.append(Paragraph(m_text, body_style))
            mit_elements.append(Spacer(1, 4))
    else:
        mit_elements.append(Paragraph("<i>No specific mitigations required for current telemetry.</i>", body_style))

    elements.append(KeepTogether(mit_elements))
    elements.append(Spacer(1, 12))

    # SECTION 10: KEY OBSERVATIONS & FACTUAL CONCLUSION
    conc_text = (
        f"<b>10. KEY OBSERVATIONS & FACTUAL CONCLUSION</b><br/><br/>"
        f"The HoneyWatch defensive platform successfully recorded and analyzed honeypot interaction across {data['tot_sessions']} "
        f"sessions, {data['tot_logins']} authentication attempts, and {data['tot_commands']} command execution payloads. "
        f"Security findings, behavioral heuristic scores, and mitigation guidance strictly reflect factual telemetry stored in the database."
    )
    t_conc_box = Table([[Paragraph(conc_text, callout_style)]], colWidths=[532])
    t_conc_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(KeepTogether([t_conc_box]))

    elements.append(Spacer(1, 16))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    elements.append(Paragraph("Official Threat Intelligence Document — Generated by <b>HoneyWatch Defensive System</b>.", ParagraphStyle('Foot', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#64748b"))))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


if __name__ == "__main__":
    pdf_bytes = generate_pdf_report("all")
    with open("HoneyWatch_Executive_Report_2026-09-25.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("Generated HoneyWatch_Executive_Report_2026-09-25.pdf successfully! Bytes:", len(pdf_bytes))
