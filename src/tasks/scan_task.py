from src.tasks.broker import broker
from src.scanner import security_scanner

@broker.task
async def run_security_scan(url: str) -> dict:
    report = await security_scanner.start_scan(url)
    return report.model_dump()