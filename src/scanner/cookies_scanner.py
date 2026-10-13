from httpx import Response

from src.scanner.base import BaseResponseScanner
from src.scanner.schemas import CookieFinding, CookiesScanReport, Severity

FLAGS = {
    'httponly': {
        'severity': Severity.HIGH,
        'description': 'Missing HttpOnly flag (cookie accessible via JavaScript / XSS)',
    },
    'secure': {
        'severity': Severity.HIGH,
        'description': 'Missing Secure flag (cookie can be transmitted over unencrypted HTTP)',
    },
    'samesite': {
        'severity': Severity.MEDIUM,
        'description': 'Missing SameSite flag (cookie sent on cross-site requests, risking CSRF)'
    },
}

class CookiesScanner(BaseResponseScanner):
    async def scan(self, response: Response) -> CookiesScanReport:
        raw_cookies: list[str] = response.headers.get_list('set-cookie')

        cookies_scan = self._check_cookies(raw_cookies)

        return CookiesScanReport(
            target_url=str(response.url),
            total_cookies=len(raw_cookies),
            has_issues=len(cookies_scan) > 0,
            findings=cookies_scan,
        )

    def _check_cookies(self, raw_cookies: list[str]) -> list[CookieFinding]:
        findings: list[CookieFinding] = []

        for cookie in raw_cookies:
            cooked_cookie = [p.strip() for p in cookie.lower().split(';')]
            for flag, flag_info in FLAGS.items():
                has_flag = any(p.startswith(flag) for p in cooked_cookie[1:])
                if not has_flag:
                    findings.append(
                        CookieFinding(
                            cookie_name=cooked_cookie[0].split('=')[0],
                            severity=flag_info['severity'],
                            description=flag_info['description'],
                        )
                    )

        return findings
