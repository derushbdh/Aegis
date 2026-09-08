import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import asyncio

from src.scanner.schemas import SSLScanReport
from src.core.config import settings

class SSLScanner:
    def _extract_hostname(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        return parsed.netloc.split(":")[0]
    
    def _get_certificate(self, hostname: str, port: int=443) -> SSLScanReport:
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                    (hostname, port), 
                    timeout=settings.SCANNER_TIMEOUT
                ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert() # dict with certificate data
            
            if not cert:
                return SSLScanReport(host=hostname, is_valid=False)
            
            not_after_str = str(cert["notAfter"])
            expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z") \
                                  .replace(tzinfo=timezone.utc)
            days_left = (expire_date - datetime.now(timezone.utc)).days

            issuer_info = {}
            for rdn in cert.get("issuer", ()):
                for key, value in rdn:
                    issuer_info[key] = value
            issuer = issuer_info.get("organizationName") \
                                or issuer_info.get("commonName") \
                                or "Unknown"
            
            return SSLScanReport(
                host=hostname,
                is_valid=days_left > 0,
                days_left=days_left,
                issuer=issuer
            )
        except Exception as e:
            return SSLScanReport(host=hostname, is_valid=False, error=str(e))
    
    async def scan(self, url) -> SSLScanReport:
        hostname = self._extract_hostname(url)
        return await asyncio.to_thread(self._get_certificate, hostname)