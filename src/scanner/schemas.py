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


class HTMLFinding(BaseModel):
    category: str
    severity: Severity
    description: str
    evidence: str | None = None


class HTMLScanReport(BaseModel):
    target_url: str
    findings: list[HTMLFinding] = []
    has_issues: bool = False
    total_issues: int = 0


class CookieFinding(BaseModel):
    cookie_name: str
    severity: Severity
    description: str


class CookiesScanReport(BaseModel):
    target_url: str
    total_cookies: int = 0
    has_issues: bool = False
    findings: list[CookieFinding] = []


class FullScanReport(BaseModel):
    url: str
    headers_report: HeadersScanReport
    ssl_report: SSLScanReport
    files_report: SensitiveFilesReport
    html_report: HTMLScanReport
    cookies_report: CookiesScanReport
