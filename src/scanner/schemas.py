from pydantic import BaseModel
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HeaderCheckResult(BaseModel):
    header_name: str
    is_present: bool
    value: str | None = None
    severity: Severity
    description: str

class HeadersScanReport(BaseModel):
    target_url: str
    headers: list[HeaderCheckResult]
    safety_percentage: float


class SSLScanReport(BaseModel):
    host: str
    is_valid: bool
    days_left: int | None = None
    issuer: str | None = None
    error: str | None = None


class FileCheckResult(BaseModel):
    path: str
    is_exposed: bool
    url: str
    severity: Severity
    description: str

class SensitiveFilesReport(BaseModel):
    target_url: str
    files: list[FileCheckResult]
    has_leaks: bool
    leaked_count: int


class FullScanReport(BaseModel):
    url: str
    headers_report: HeadersScanReport
    ssl_report: SSLScanReport
    files_report: SensitiveFilesReport