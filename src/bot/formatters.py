import html


def format_scan_report(report: dict) -> str:
    url = html.escape(report.get("url", "Unknown"))
    ssl = report.get("ssl_report", {})
    headers = report.get("headers_report", {})
    files = report.get("files_report", {})
    html_info = report.get("html_report", {})
    cookies_info = report.get("cookies_report", {})

    lines = [
        "🛡 <b>Aegis Security Audit Report</b>",
        f"🌐 <b>Target:</b> <code>{url}</code>",
        "",
        "🔒 <b>SSL/TLS Certificate:</b>",
    ]

    if ssl.get("is_valid"):
        days_left = ssl.get("days_left", 0)
        issuer = html.escape(str(ssl.get("issuer") or "Unknown"))
        days_emoji = "🟢" if days_left > 30 else ("🟡" if days_left > 7 else "🔴")
        lines.append(f"  • Status: {days_emoji} Valid (<b>{days_left}</b> days remaining)")
        lines.append(f"  • Issuer: <i>{issuer}</i>")
    else:
        err = html.escape(str(ssl.get("error") or "Verification error"))
        lines.append(f"  • Status: 🔴 <b>Invalid / Error</b> ({err})")

    lines.append("")

    safety_pct = headers.get("safety_percentage", 0.0)
    lines.append(f"📋 <b>Security Headers:</b> (score: <b>{safety_pct:.0f}%</b>)")
    for h in headers.get("headers", []):
        h_name = html.escape(h.get("header_name", ""))
        if h.get("is_present"):
            lines.append(f"  ✅ <code>{h_name}</code>")
        else:
            sev = h.get("severity", "medium").upper()
            lines.append(f"  ❌ <code>{h_name}</code> <i>[risk: {sev}]</i>")

    lines.append("")

    has_leaks = files.get("has_leaks", False)
    lines.append("📁 <b>Sensitive Files:</b>")
    if not has_leaks:
        lines.append("  ✅ No critical file leaks (.env, .git, docker-compose) detected.")
    else:
        leaked_count = files.get("leaked_count", 0)
        lines.append(f"  🚨 <b>Warning: File leaks detected (found: {leaked_count})!</b>")
        for f in files.get("files", []):
            if f.get("is_exposed"):
                f_path = html.escape(f.get("path", ""))
                lines.append(f"    • ⚠️ <code>{f_path}</code> is publicly accessible!")

    lines.append("")
    lines.append("🌐 <b>HTML & Markup Security:</b>")
    has_html_issues = html_info.get("has_issues", False)
    if not has_html_issues:
        lines.append("  ✅ Forms, comments, and links are secure.")
    else:
        total_issues = html_info.get("total_issues", 0)
        lines.append(f"  ⚠️ <b>Markup risks detected (found: {total_issues}):</b>")
        for finding in html_info.get("findings", []):
            sev = str(finding.get("severity") or "low").upper()
            desc = html.escape(str(finding.get("description", "")))
            lines.append(f"    • <i>[{sev}]</i> {desc}")

    lines.append("")
    lines.append("🍪 <b>Cookie Security:</b>")
    total_cookies = cookies_info.get("total_cookies", 0)
    has_cookie_issues = cookies_info.get("has_issues", False)
    if total_cookies == 0:
        lines.append("  ℹ️ No cookies set by the host.")
    elif not has_cookie_issues:
        lines.append(f"  ✅ All cookies ({total_cookies}) are secured with proper flags.")
    else:
        c_findings = cookies_info.get("findings", [])
        lines.append(f"  ⚠️ <b>Cookie risks detected (issues: {len(c_findings)}):</b>")
        for cf in c_findings:
            c_name = html.escape(str(cf.get("cookie_name", "")))
            sev = str(cf.get("severity") or "medium").upper()
            desc = html.escape(str(cf.get("description", "")))
            lines.append(f"    • <code>{c_name}</code>: <i>[{sev}]</i> {desc}")

    return "\n".join(lines)


from src.ai.schemas import AIConsultantReport


def format_ai_report(ai_report: AIConsultantReport) -> str:
    lines = [
        "🤖 <b>White-Hat Consultant Verdict (AI):</b>",
        f"<i>«{html.escape(ai_report.verdict)}»</i>",
        "",
    ]
    if ai_report.risks:
        lines.append("⚠️ <b>Identified Risks:</b>")
        for risk in ai_report.risks:
            lines.append(f"  • {html.escape(risk)}")
    else:
        lines.append("✅ <b>No vulnerabilities or critical risks detected.</b>")

    if ai_report.recommendations:
        lines.append("")
        lines.append("🛠 <b>Recommendations:</b>")
        for rec in ai_report.recommendations:
            lines.append(f"  • {html.escape(rec)}")

    return "\n".join(lines)

def format_history_report(records: list) -> str:
    if not records:
        return (
            "📭 <b>You don't have any audit history yet.</b>\n\n"
            "Run your first scan with:\n"
            "<code>/scan https://example.com</code>"
        )

    lines = [
        "📜 <b>Recent Security Audits History:</b>",
        ""
    ]

    for i, scan in enumerate(records, 1):
        dt_str = scan.created_at.strftime("%d.%m.%Y %H:%M") if scan.created_at else "Unknown"
        ssl_status = "🟢 SSL OK" if scan.ssl_valid else "🔴 No SSL"
        leaks_status = "🚨 Leaks!" if scan.has_leaks else "🛡 No Leaks"

        lines.append(f"<b>{i}. 🌐 {html.escape(scan.target_url)}</b>")
        lines.append(f"   📅 <i>{dt_str}</i>")
        lines.append(f"   📊 Headers: <b>{scan.headers_score}%</b> | {ssl_status} | {leaks_status}")

        if scan.ai_verdict:
            short_verdict = scan.ai_verdict.split("\n")[0][:100]
            lines.append(f"   🤖 <i>«{html.escape(short_verdict)}...»</i>")

        lines.append("")

    return "\n".join(lines)