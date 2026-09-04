import httpx
from src.core.config import settings
from src.scanner.schemas import HeaderCheckResult, HeadersScanReport, Severity

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "Принудительное шифрование трафика (HSTS)"
    },
    "X-Frame-Options": {
        "severity": Severity.HIGH,
        "description": "Защита от атак через скрытые рамки (Clickjacking)"
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "Запрет браузеру угадывать тип файлов (MIME-sniffing)"
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "Ограничение источников скриптов и контента (CSP)"
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Контроль утечки путей в заголовке Referer"
    },
}

class HeadersScanner:
    async def scan(self, url: str) -> HeadersScanReport:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        async with httpx.AsyncClient(
            timeout=settings.SCANNER_TIMEOUT,
            headers={"User-Agent": settings.SCANNER_USER_AGENT},
            follow_redirects=True
        ) as client:
            response = await client.get(url)
        
        results: list[HeaderCheckResult] = []

        count = 0
        for header_name, meta in SECURITY_HEADERS.items():
            is_present = header_name in response.headers
            value = response.headers.get(header_name) if is_present else None

            if is_present:
                count += 1
            
            results.append(
                HeaderCheckResult(
                    header_name=header_name,
                    is_present=is_present,
                    value=value,
                    severity=meta["severity"],
                    description=meta["description"]
                )
            )
        
        safety_percentage = (count / len(SECURITY_HEADERS)) * 100.0


        return HeadersScanReport(
            target_url=url,
            headers=results,
            safety_percentage=round(safety_percentage, 1)
        )