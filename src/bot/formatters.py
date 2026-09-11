import html


def format_scan_report(report: dict) -> str:
    """
    Форматирует результат сканирования в красивое HTML-сообщение для Telegram.
    """
    url = html.escape(report.get("url", "Unknown"))
    ssl = report.get("ssl_report", {})
    headers = report.get("headers_report", {})
    files = report.get("files_report", {})

    lines = [
        "🛡 <b>Aegis Security Audit Report</b>",
        f"🌐 <b>Цель:</b> <code>{url}</code>",
        "",
        "🔒 <b>SSL/TLS Сертификат:</b>",
    ]

    # --- Блок SSL ---
    if ssl.get("is_valid"):
        days_left = ssl.get("days_left", 0)
        issuer = html.escape(str(ssl.get("issuer") or "Unknown"))
        days_emoji = "🟢" if days_left > 30 else ("🟡" if days_left > 7 else "🔴")
        lines.append(f"  • Статус: {days_emoji} Валиден (осталось дней: <b>{days_left}</b>)")
        lines.append(f"  • Издатель: <i>{issuer}</i>")
    else:
        err = html.escape(str(ssl.get("error") or "Ошибка проверки"))
        lines.append(f"  • Статус: 🔴 <b>Недействителен / Ошибка</b> ({err})")

    lines.append("")

    # --- Блок Security Headers ---
    safety_pct = headers.get("safety_percentage", 0.0)
    lines.append(f"📋 <b>Заголовки безопасности:</b> (оценка: <b>{safety_pct:.0f}%</b>)")
    for h in headers.get("headers", []):
        h_name = html.escape(h.get("header_name", ""))
        if h.get("is_present"):
            lines.append(f"  ✅ <code>{h_name}</code>")
        else:
            sev = h.get("severity", "medium").upper()
            lines.append(f"  ❌ <code>{h_name}</code> <i>[риск: {sev}]</i>")

    lines.append("")

    # --- Блок Конфиденциальных файлов ---
    has_leaks = files.get("has_leaks", False)
    lines.append("📁 <b>Конфиденциальные файлы:</b>")
    if not has_leaks:
        lines.append("  ✅ Утечек критических файлов (.env, .git, docker-compose) не обнаружено.")
    else:
        leaked_count = files.get("leaked_count", 0)
        lines.append(f"  🚨 <b>Внимание: обнаружены утечки (найдено: {leaked_count})!</b>")
        for f in files.get("files", []):
            if f.get("is_exposed"):
                f_path = html.escape(f.get("path", ""))
                lines.append(f"    • ⚠️ <code>{f_path}</code> доступен публично!")

    return "\n".join(lines)