"""
API Security Testing Module
Analyzes backend API security for mobile applications.
"""
import re
import json
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger("APISecurity")


class APISecurityTester:
    """Tests API security for mobile application backends."""

    def __init__(self, file_path: Path, api_endpoints: list = None):
        self.file_path = file_path
        self.api_endpoints = api_endpoints or []
        self.findings = []
        self.api_analysis = []

    def analyze(self) -> dict:
        """Run API security analysis."""
        logger.info(f"Starting API security analysis: {self.file_path.name}")

        self._analyze_discovered_endpoints()
        self._check_auth_patterns()
        self._check_data_exposure()
        self._check_idor_patterns()
        self._check_rate_limiting()
        self._check_api_versioning()
        self._check_graphql_security()
        self._check_injection_patterns()

        return {
            "api_endpoints_analyzed": len(self.api_endpoints),
            "api_analysis": self.api_analysis,
            "findings": self.findings,
        }

    def _get_strings(self) -> list[dict]:
        """Extract strings from package."""
        strings = []
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    if info.file_size > 5_000_000:
                        continue
                    try:
                        raw = zf.read(info.filename)
                        text = raw.decode("utf-8", errors="ignore")
                        strings.append({"file": info.filename, "content": text})
                    except Exception:
                        pass
        except Exception:
            pass
        return strings

    def _analyze_discovered_endpoints(self):
        """Analyze discovered API endpoints for security issues."""
        for ep in self.api_endpoints:
            url = ep.get("url", "")
            parsed = urlparse(url)

            analysis = {
                "url": url,
                "scheme": parsed.scheme,
                "host": parsed.hostname or "",
                "path": parsed.path,
                "issues": [],
            }

            # Check for HTTP
            if parsed.scheme == "http":
                analysis["issues"].append("Uses HTTP instead of HTTPS")

            # Check for sensitive paths
            sensitive_paths = ["/admin", "/debug", "/test", "/internal", "/swagger",
                               "/api-docs", "/graphql", "/phpinfo", "/.env", "/config"]
            for sp in sensitive_paths:
                if sp in parsed.path.lower():
                    analysis["issues"].append(f"Sensitive endpoint exposed: {sp}")

            # Check for version in path
            if not re.search(r"/v\d+/", parsed.path):
                analysis["issues"].append("No API versioning detected")

            # Check for credentials in URL
            if parsed.username or parsed.password:
                analysis["issues"].append("Credentials embedded in URL")
                self.findings.append({
                    "title": "Credentials in API URL",
                    "severity": "critical",
                    "description": f"API URL contains embedded credentials: {url[:50]}...",
                    "category": "api",
                    "owasp": "API2",
                    "cwe": "CWE-798",
                    "evidence": f"URL with credentials: {url[:30]}...",
                })

            # Check for API key in URL
            if re.search(r"[?&](api[_-]?key|apikey|key|token)=", url, re.IGNORECASE):
                analysis["issues"].append("API key passed in URL query parameter")
                self.findings.append({
                    "title": "API Key in URL",
                    "severity": "high",
                    "description": "API key is passed as a URL query parameter. "
                                   "This can be logged and exposed in browser history.",
                    "category": "api",
                    "owasp": "API2",
                    "cwe": "CWE-598",
                    "evidence": f"API key in URL: {url[:50]}...",
                })

            self.api_analysis.append(analysis)

    def _check_auth_patterns(self):
        """Check authentication implementation patterns."""
        auth_issues = {
            "Hardcoded Auth Header": (
                r"(?i)(Authorization|X-API-Key)\s*[:=]\s*['\"][^'\"]+['\"]",
                "Hardcoded authentication header found",
                "critical",
            ),
            "Basic Auth Usage": (
                r"(?i)Basic\s+[A-Za-z0-9+/]+=*",
                "Basic Authentication is used — credentials can be easily decoded",
                "high",
            ),
            "No Auth Check": (
                r"(?i)@(NoAuth|PublicEndpoint|PermitAll)",
                "Endpoint may lack authentication requirement",
                "medium",
            ),
            "Token in localStorage": (
                r"(?i)localStorage\.(setItem|getItem).*(?:token|auth|session)",
                "Authentication token stored in localStorage (accessible via XSS)",
                "medium",
            ),
            "Insecure Token Storage": (
                r"(?i)(?:SharedPreferences|NSUserDefaults).*(?:auth|token|session)",
                "Authentication token stored insecurely",
                "high",
            ),
        }

        for item in self._get_strings():
            for issue_name, (pattern, desc, severity) in auth_issues.items():
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": f"Authentication Issue: {issue_name}",
                        "severity": severity,
                        "description": desc,
                        "category": "api",
                        "owasp": "API2",
                        "cwe": "CWE-287",
                        "evidence": f"Found in {item['file']}",
                    })

    def _check_data_exposure(self):
        """Check for excessive data exposure in API responses."""
        exposure_patterns = {
            "User Data Fields": (
                r"(?i)(password|ssn|social_security|credit_card|card_number|cvv|pin_code)",
                "API may expose sensitive user data fields",
            ),
            "Debug Information": (
                r"(?i)(stack_trace|stacktrace|debug_info|internal_error)",
                "API may expose debug/internal information",
            ),
            "Database Fields": (
                r"(?i)(db_password|database_url|connection_string)",
                "API may expose database connection details",
            ),
        }

        for item in self._get_strings():
            for issue_name, (pattern, desc) in exposure_patterns.items():
                matches = re.findall(pattern, item["content"])
                if matches:
                    self.findings.append({
                        "title": f"Data Exposure Risk: {issue_name}",
                        "severity": "medium",
                        "description": desc,
                        "category": "api",
                        "owasp": "API3",
                        "cwe": "CWE-200",
                        "evidence": f"Sensitive fields in {item['file']}: {', '.join(set(matches[:5]))}",
                    })

    def _check_idor_patterns(self):
        """Check for IDOR vulnerability patterns."""
        idor_patterns = [
            r"(?i)/users?/\{?id\}?",
            r"(?i)/accounts?/\{?id\}?",
            r"(?i)/orders?/\{?id\}?",
            r"(?i)/profiles?/\{?\w*[Ii]d\}?",
            r"(?i)user_id\s*=\s*(?:request|params|args)",
        ]

        for item in self._get_strings():
            for pattern in idor_patterns:
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": "Potential IDOR Vulnerability",
                        "severity": "high",
                        "description": "API endpoints use predictable identifiers for accessing resources. "
                                       "Verify proper authorization checks are in place.",
                        "category": "api",
                        "owasp": "API1",
                        "cwe": "CWE-639",
                        "evidence": f"ID-based resource access in {item['file']}",
                    })
                    return  # One finding is enough

    def _check_rate_limiting(self):
        """Check for rate limiting implementation."""
        rate_limit_patterns = [
            r"(?i)rate.?limit", r"(?i)throttl",
            r"(?i)X-RateLimit", r"(?i)retry-after",
            r"(?i)too.?many.?requests", r"(?i)429",
        ]

        found = False
        for item in self._get_strings():
            for pattern in rate_limit_patterns:
                if re.search(pattern, item["content"]):
                    found = True
                    break
            if found:
                break

        if not found:
            self.findings.append({
                "title": "No Rate Limiting Detected",
                "severity": "medium",
                "description": "No rate limiting implementation found. APIs without rate limiting "
                               "are vulnerable to brute force and DoS attacks.",
                "category": "api",
                "owasp": "API4",
                "cwe": "CWE-770",
                "evidence": "No rate limiting patterns found in code",
            })

    def _check_api_versioning(self):
        """Check API versioning practices."""
        has_versioning = False
        for ep in self.api_endpoints:
            if re.search(r"/v\d+/", ep.get("url", "")):
                has_versioning = True
                break

        if not has_versioning and len(self.api_endpoints) > 0:
            self.findings.append({
                "title": "No API Versioning",
                "severity": "low",
                "description": "API endpoints do not appear to use versioning. "
                               "Lack of versioning can lead to backward compatibility issues.",
                "category": "api",
                "owasp": "API9",
                "cwe": "CWE-1059",
                "evidence": "No /v{n}/ pattern found in API URLs",
            })

    def _check_graphql_security(self):
        """Check for GraphQL-specific security issues."""
        graphql_patterns = {
            "GraphQL Introspection": (
                r"(?i)introspection|__schema|__type",
                "GraphQL introspection may be enabled, exposing the full API schema",
                "medium",
            ),
            "GraphQL Endpoint": (
                r"(?i)/graphql",
                "GraphQL endpoint detected — verify query depth limits and rate limiting",
                "low",
            ),
        }

        for item in self._get_strings():
            for issue_name, (pattern, desc, severity) in graphql_patterns.items():
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": f"GraphQL: {issue_name}",
                        "severity": severity,
                        "description": desc,
                        "category": "api",
                        "owasp": "API9",
                        "cwe": "CWE-200",
                        "evidence": f"Found in {item['file']}",
                    })

    def _check_injection_patterns(self):
        """Check for potential injection vulnerabilities."""
        injection_patterns = {
            "SQL Injection": (
                r"(?i)(rawQuery|execSQL|execute).*\+.*(?:user|input|param|request)",
                "Potential SQL injection — user input concatenated with SQL query",
                "CWE-89",
            ),
            "Command Injection": (
                r"(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder).*\+",
                "Potential command injection — user input in system command",
                "CWE-78",
            ),
            "Path Traversal": (
                r"(?i)(new File|FileOutputStream).*\+.*(?:user|input|param|request)",
                "Potential path traversal — user input in file path",
                "CWE-22",
            ),
            "XSS Risk": (
                r"(?i)loadUrl.*javascript:|evaluateJavascript.*\+",
                "Potential XSS — dynamic JavaScript execution in WebView",
                "CWE-79",
            ),
        }

        for item in self._get_strings():
            for issue_name, (pattern, desc, cwe) in injection_patterns.items():
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": f"Injection Risk: {issue_name}",
                        "severity": "high",
                        "description": desc,
                        "category": "api",
                        "owasp": "API4" if "SQL" in issue_name else "API8",
                        "cwe": cwe,
                        "evidence": f"Found in {item['file']}",
                    })
