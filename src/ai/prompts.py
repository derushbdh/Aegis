import json

SYSTEM_PROMPT = """You are a lead web application security engineer and ethical security consultant (White-Hat Security Auditor).
Your task is to analyze the technical website scan report and provide an objective expert assessment for developers.

CRITICAL RULES:
1. Base your analysis STRICTLY on the facts provided in the report. Do not invent or assume vulnerabilities (no hallucinations).
2. If a file or component is marked as safe (e.g., no file leaks, no HTML or cookie issues), it is STRICTLY PROHIBITED to claim it is exposed or vulnerable.
3. If there are no vulnerabilities or leaks (100% headers, valid SSL, 0 file leaks, 0 HTML issues, secure cookies):
   - The "risks" field MUST be an empty list: []
   - The "verdict" must contain a positive evaluation of the website's robust security posture.
   - The "recommendations" can provide general maintenance/monitoring suggestions or be an empty list.
4. If problems are detected:
   - In "risks", describe ONLY REAL findings detected in the report (missing headers, invalid SSL, exposed files, HTML/form/comment vulnerabilities, insecure cookies).
   - In "recommendations", provide concrete mitigation steps for each identified issue (including cookie flags HttpOnly, Secure, SameSite, CSRF tokens, password over HTTPS).
5. Output response STRICTLY in valid JSON format matching this schema:
{
  "verdict": "Brief summary verdict on website security posture in English",
  "risks": ["risk 1", "risk 2"],
  "recommendations": ["recommendation 1", "recommendation 2"]
}
Respond entirely in English.
"""


def build_user_prompt(scan_data: dict) -> str:
    url = scan_data.get("url", "Not specified")
    ssl = scan_data.get("ssl_report", {})
    headers = scan_data.get("headers_report", {})
    files = scan_data.get("files_report", {})
    html = scan_data.get("html_report", {})
    cookies = scan_data.get("cookies_report", {})

    # SSL summary
    if ssl.get("is_valid"):
        ssl_summary = f"Valid ({ssl.get('days_left')} days remaining), issuer: {ssl.get('issuer')}"
    else:
        ssl_summary = f"ERROR or invalid ({ssl.get('error')})"

    # Headers summary - only missing ones
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

    # Exposed files summary - ONLY genuinely exposed files
    exposed_files = [
        {
            "path": f.get("path"),
            "severity": f.get("severity"),
            "description": f.get("description"),
        }
        for f in files.get("files", [])
        if f.get("is_exposed")
    ]

    # HTML vulnerabilities summary
    html_findings = [
        {
            "category": f.get("category"),
            "severity": f.get("severity"),
            "description": f.get("description"),
            "evidence": f.get("evidence"),
        }
        for f in html.get("findings", [])
    ]

    # Cookies vulnerabilities summary
    cookie_findings = [
        {
            "cookie_name": cf.get("cookie_name"),
            "severity": cf.get("severity"),
            "description": cf.get("description"),
        }
        for cf in cookies.get("findings", [])
    ]
    total_cookies = cookies.get("total_cookies", 0)
    if total_cookies == 0:
        cookies_summary = "Host does not set any cookies"
    elif not cookie_findings:
        cookies_summary = f"All cookies ({total_cookies}) are secured with HttpOnly, Secure, and SameSite flags"
    else:
        cookies_summary = cookie_findings

    clean_summary = {
        "target_url": url,
        "ssl_status": ssl_summary,
        "headers_score": f"{headers_pct:.0f}%",
        "missing_security_headers": missing_headers if missing_headers else "All critical security headers are configured properly (100%)",
        "exposed_sensitive_files": exposed_files if exposed_files else "No leaks. All sensitive files are protected and not publicly accessible",
        "html_vulnerabilities": html_findings if html_findings else "No HTML structure vulnerabilities (insecure forms, comments with secrets, reverse tabnabbing) detected",
        "cookies_vulnerabilities": cookies_summary,
    }

    return (
        "Analyze the following technical security audit results:\n"
        f"```json\n{json.dumps(clean_summary, ensure_ascii=False, indent=2)}\n```\n"
        "Generate an expert verdict, list of risks, and actionable recommendations in JSON format in English.\n"
        "IMPORTANT: If no vulnerabilities were found and no files leaked, the 'risks' list MUST be empty [], "
        "and the verdict must confirm strong security posture."
    )
