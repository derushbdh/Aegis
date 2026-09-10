import asyncio

from src.core.config import settings
from src.scanner import HeadersScanner, SSLScanner, SensitiveFilesScanner
from src.scanner.schemas import FullScanReport

class SecurityScanner:
    def __init__(self):
        self.scanners = [
            HeadersScanner(),
            SSLScanner(),
            SensitiveFilesScanner()
        ]

    async def start_scan(self, url: str) -> FullScanReport:
        headers_report, ssl_report, files_report = await asyncio.gather(
            *(scanner.scan(url) for scanner in self.scanners)
        )

        return FullScanReport(
            url=url,
            headers_report=headers_report,
            ssl_report=ssl_report,
            files_report=files_report
        )

security_scanner = SecurityScanner()