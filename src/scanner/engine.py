from time import time
import asyncio
import httpx

from src.scanner import HeadersScanner, SSLScanner, SensitiveFilesScanner, HTMLScanner, CookiesScanner
from src.scanner.schemas import FullScanReport
from src.core.config import settings


class SecurityScanner:
    def __init__(self):
        self.ssl_scanner = SSLScanner()
        self.files_scanner = SensitiveFilesScanner()
        self.headers_scanner = HeadersScanner()
        self.html_scanner = HTMLScanner()
        self.cookies_scanner = CookiesScanner()

    async def start_scan(self, url: str) -> FullScanReport:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        async with httpx.AsyncClient(
            timeout=settings.SCANNER_TIMEOUT,
            headers={'User-agent': settings.SCANNER_USER_AGENT},
            follow_redirects=True,
        ) as client:
            response, ssl_report, files_report = await asyncio.gather(
                client.get(url),
                self.ssl_scanner.scan(url),
                self.files_scanner.scan(url),
            )

        headers_report, html_report, cookies_report = await asyncio.gather(
            self.headers_scanner.scan(response),
            self.html_scanner.scan(response),
            self.cookies_scanner.scan(response),
        )

        return FullScanReport(
            url=url,
            headers_report=headers_report,
            ssl_report=ssl_report,
            files_report=files_report,
            html_report=html_report,
            cookies_report=cookies_report,
        )


security_scanner = SecurityScanner()
