import json

SYSTEM_PROMPT = """Ты — ведущий инженер по безопасности веб-приложений и этичный консультант (White-Hat Security Auditor).
Твоя задача — проанализировать технический отчет сканирования сайта и предоставить объективное экспертное заключение для разработчиков.

КРИТИЧЕСКИЕ ПРАВИЛА:
1. Опирайся ИСКЛЮЧИТЕЛЬНО на факты из отчета. Строго запрещено придумывать или предполагать уязвимости (никаких галлюцинаций).
2. Если файл или уязвимость помечены как безопасные (например, утечек файлов нет), КАТЕГОРИЧЕСКИ ЗАПРЕЩЕНО писать, что файл доступен или утек.
3. Если уязвимостей и утечек нет (100% заголовков, валидный SSL, 0 утечек):
   - Поле "risks" ОБЯЗАНО быть пустым списком: []
   - "verdict" должен содержать положительную оценку отличной защиты сайта.
   - "recommendations" могут содержать общие рекомендации по дальнейшему мониторингу или быть пустым списком.
4. Если проблемы обнаружены:
   - В "risks" опиши ТОЛЬКО РЕАЛЬНО обнаруженные проблемы (отсутствующие заголовки, невалидный SSL, реально утекшие файлы).
   - В "recommendations" дай конкретные шаги по устранению каждой обнаруженной проблемы.
5. Ответ верни СТРОГО в виде валидного JSON-объекта со следующими полями:
{
  "verdict": "Краткий общий вердикт о состоянии защиты сайта",
  "risks": ["риск 1", "риск 2"],
  "recommendations": ["рекомендация 1", "рекомендация 2"]
}
"""


def build_user_prompt(scan_data: dict) -> str:
    url = scan_data.get("url", "Не указан")
    ssl = scan_data.get("ssl_report", {})
    headers = scan_data.get("headers_report", {})
    files = scan_data.get("files_report", {})

    # SSL summary
    if ssl.get("is_valid"):
        ssl_summary = f"Действителен (осталось дней: {ssl.get('days_left')}), издатель: {ssl.get('issuer')}"
    else:
        ssl_summary = f"ОШИБКА или недействителен ({ssl.get('error')})"

    # Headers summary - только отсутствующие
    missing_headers = [
        {
            "header": h.get("header_name"),
            "severity": h.get("severity"),
            "description": h.get("description"),
        }
        for h in headers.get("headers", [])
        if not h.get("is_present")
    ]
    headers_pct = headers.get("safety_percentage", 0)

    # Exposed files summary - ТОЛЬКО реально утекшие файлы
    exposed_files = [
        {
            "path": f.get("path"),
            "severity": f.get("severity"),
            "description": f.get("description"),
        }
        for f in files.get("files", [])
        if f.get("is_exposed")
    ]

    clean_summary = {
        "target_url": url,
        "ssl_status": ssl_summary,
        "headers_score": f"{headers_pct:.0f}%",
        "missing_security_headers": missing_headers if missing_headers else "Все 5 ключевых заголовков безопасности настроены правильно (100%)",
        "exposed_sensitive_files": exposed_files if exposed_files else "Утечек нет. Все конфиденциальные файлы (.env, .git, docker-compose и др.) защищены и недоступны публично",
    }

    return (
        "Проанализируй следующие результаты технического аудита безопасности:\n"
        f"```json\n{json.dumps(clean_summary, ensure_ascii=False, indent=2)}\n```\n"
        "Сформируй экспертный вердикт, список рисков и рекомендации по исправлению в формате JSON.\n"
        "ВАЖНО: Если уязвимости отсутствуют и файлы не утекли, список risks должен быть пустым [], "
        "а вердикт должен подтверждать надежную защиту сайта."
    )
