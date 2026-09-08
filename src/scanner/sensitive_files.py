import asyncio
import httpx

from src.core.config import settings
from src.scanner.schemas import FileCheckResult, SensitiveFilesReport, Severity
from src.scanner.base import BaseScanner

TARGET_FILES = {
    "/.env": {
        "severity": Severity.CRITICAL,
        "description": "Файл переменных окружения с секретами и паролями",
        "signature": "="  # в файле env обязательно есть знак равенства (KEY=VALUE)
    },
    "/.git/HEAD": {
        "severity": Severity.CRITICAL,
        "description": "Служебный файл Git (утечка исходного кода)",
        "signature": "ref: refs/"  # стандартное начало любого git-файла HEAD
    },
    "/docker-compose.yml": {
        "severity": Severity.HIGH,
        "description": "Конфигурация контейнеров Docker Compose",
        "signature": "services:"  # в docker-compose всегда есть секция services
    }
}


class SensitiveFilesScanner(BaseScanner):
    def _is_file_exposed(
        self, response: httpx.Response, 
        signature: str
        ) -> bool:
        if response.status_code == 200 and \
            signature in response.text and \
            "<html" not in response.text.lower():
            return True
        return False
    
    async def _check_file(
        self, client: httpx.AsyncClient,
        base_url: str, 
        path: str, 
        meta: dict
        ) -> FileCheckResult:
        file_url = f"{base_url.rstrip('/')}{path}"

        try:
            response = await client.get(file_url)
            is_exposed = self._is_file_exposed(response, meta["signature"])
        except httpx.RequestError:
            is_exposed = False
        
        return FileCheckResult(
            path=path, 
            is_exposed=is_exposed,
            url=file_url,
            severity=meta["severity"],
            description=meta["description"]
        )

        
    async def scan(
        self, 
        url: str
        ) -> SensitiveFilesReport:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        async with httpx.AsyncClient(
            timeout=settings.SCANNER_TIMEOUT,
            headers={"User-agent": settings.SCANNER_USER_AGENT},
            follow_redirects=True
        ) as client:
            tasks = [
                self._check_file(client, url, path, meta) 
                for path, meta in TARGET_FILES.items()
            ]

            results = await asyncio.gather(*tasks)

        leaked_count = sum(True for r in results if r.is_exposed)
        
        return SensitiveFilesReport(
            target_url=url,
            files=results,
            has_leaks=leaked_count > 0,
            leaked_count=leaked_count
        )