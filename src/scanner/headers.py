from httpx import Response

from src.scanner.schemas import HeaderCheckResult, HeadersScanReport, Severity
from src.scanner.base import BaseResponseScanner

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "Enforces encrypted HTTPS connections (HSTS)"
    },
    "X-Frame-Options": {
        "severity": Severity.HIGH,
        "description": "Protects against clickjacking attacks"
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "Prevents MIME-sniffing vulnerabilities"
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "Restricts unauthorized script execution and content sources (CSP)"
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Controls leakage of URL paths in the Referer header"
    },
}

class HeadersScanner(BaseResponseScanner):
    async def scan(self, response: Response) -> HeadersScanReport:
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
            target_url=str(response.url),
            headers=results,
            safety_percentage=round(safety_percentage, 1)
        )