import httpx

from src.core.config import settings
from src.scanner.base import BaseScanner
from src.scanner.schemas import CookieFinding, CookiesScanReport, Severity

FLAGS = {
    'httponly': {
        'severity': Severity.HIGH,
        'description': 'Denies to read cookie with JS',
    },
    'secure': {
        'severity': Severity.HIGH,
        'description': 'Allows to transport cookies only with HTTPS protocol',
    },
    'samesite': {
        'severity': Severity.MEDIUM,
        'description': 'Controls cookie transport throughout redirects from third-party sites'
    },
}

class CookiesScanner(BaseScanner):
    async def scan(self, url: str) -> CookiesScanReport:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        async with httpx.AsyncClient(
            timeout=settings.SCANNER_TIMEOUT,
            headers={'User-agent': settings.SCANNER_USER_AGENT},
            follow_redirects=True,
        ) as client:
            response = await client.get(url)

        raw_cookies: list[str] = response.headers.get_list('set-cookie')

        cookies_scan = self._check_cookies(raw_cookies)

        return CookiesScanReport(
            target_url=url,
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
