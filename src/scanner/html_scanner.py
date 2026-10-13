import httpx
from src.core.config import settings
from bs4 import BeautifulSoup, Comment

from src.scanner.base import BaseScanner
from src.scanner.schemas import HTMLFinding, HTMLScanReport, Severity

VULNERABLE_COMMENTS = {
    "password": {
        "severity": Severity.HIGH,
        "description": "Potential password exposure in HTML comment",
    },
    "passwd": {
        "severity": Severity.HIGH,
        "description": "Potential password exposure in HTML comment",
    },
    "api_key": {
        "severity": Severity.HIGH,
        "description": "Potential API key leak in HTML comment",
    },
    "token": {
        "severity": Severity.HIGH,
        "description": "Potential authorization token leak in HTML comment",
    },
    "secret": {
        "severity": Severity.HIGH,
        "description": "Potential secret or private key leak in HTML comment",
    },

    "localhost": {
        "severity": Severity.MEDIUM,
        "description": "Disclosure of local address or staging environment",
    },
    "127.0.0.1": {
        "severity": Severity.MEDIUM,
        "description": "Disclosure of internal IP address",
    },
    "/var/www": {
        "severity": Severity.MEDIUM,
        "description": "Disclosure of server filesystem path",
    },

    "todo": {
        "severity": Severity.LOW,
        "description": "Developer note (TODO) left in production code",
    },
    "fixme": {
        "severity": Severity.LOW,
        "description": "Unresolved issue note (FIXME) in production code",
    },
    "hack": {
        "severity": Severity.LOW,
        "description": "Temporary workaround note (HACK) in production code",
    },
}


class HTMLScanner(BaseScanner):
    async def scan(self, url: str) -> HTMLScanReport:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        async with httpx.AsyncClient(
            timeout=settings.SCANNER_TIMEOUT,
            headers={'User-agent': settings.SCANNER_USER_AGENT},
            follow_redirects=True
        ) as client:
            response = await client.get(url)

        findings: list[HTMLFinding] = []

        soup = BeautifulSoup(response.text, 'html.parser')

        findings.extend(self._check_comments(soup))
        findings.extend(self._check_forms(soup))
        findings.extend(self._check_links(soup))

        return HTMLScanReport(
            target_url=url,
            findings=findings,
            has_issues=(len(findings) > 0),
            total_issues=len(findings),
        )

    def _check_comments(self, soup: BeautifulSoup) -> list[HTMLFinding]:
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))

        findings: list[HTMLFinding] = []

        for comment in comments:
            text = comment.lower()
            for keyword, info in VULNERABLE_COMMENTS.items():
                if keyword in text:
                    findings.append(
                        HTMLFinding(
                            category='comment',
                            severity=info['severity'],
                            description=info['description'],
                            evidence=f'<!-- {comment.strip()[:100]} -->',
                        )
                    )

                    break

        return findings


    def _check_forms(self, soup: BeautifulSoup) -> list[HTMLFinding]:
        forms = soup.find_all('form')
        findings: list[HTMLFinding] = []

        for form in forms:
            action = str(form.get('action', '')).strip()
            method = str(form.get('method', 'get')).lower()
            inputs = form.find_all('input')

            if action.startswith('http://'):
                findings.append(
                    HTMLFinding(
                        category='forms',
                        severity=Severity.HIGH,
                        description='Insecure form action submitting data over unencrypted HTTP',
                        evidence=f'Line {form.sourceline}: {str(form)[:120]}',
                    )
                )

            has_password = any(inp.get('type') == 'password' for inp in inputs)
            if method == 'get' and has_password:
                findings.append(
                    HTMLFinding(
                        category='forms',
                        severity=Severity.HIGH,
                        description='Form submits password using GET method (exposed in URL query)',
                        evidence=f'Line {form.sourceline}: {str(form)[:120]}',
                    )
                )

            has_csrf = any(inp.get('type') == 'hidden' for inp in inputs)
            if method == 'post' and not has_csrf:
                findings.append(
                    HTMLFinding(
                        category='forms',
                        severity=Severity.HIGH,
                        description='POST form lacks CSRF token protection',
                        evidence=f'Line {form.sourceline}: {str(form)[:120]}',
                    )
                )

        return findings

    def _check_links(self, soup: BeautifulSoup) -> list[HTMLFinding]:
        findings: list[HTMLFinding] = []

        links = soup.find_all('a', href=True)

        for link in links:
            target = str(link.get('target')).lower()
            if target != '_blank':
                continue

            rel = link.get('rel', None)
            has_protection = False
            if rel is not None:
                has_protection = 'noopener' in rel or 'noreferrer' in rel

            if not has_protection:
                findings.append(
                    HTMLFinding(
                        category='links',
                        severity=Severity.LOW,
                        description='Target blank link missing rel="noopener noreferrer" (Reverse Tabnabbing)',
                        evidence=f'Line {link.sourceline}: {str(link)[:100]}',
                    )
                )

        return findings
