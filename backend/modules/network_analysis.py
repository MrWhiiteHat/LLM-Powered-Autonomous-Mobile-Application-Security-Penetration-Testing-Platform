"""
Network Security Analysis Module
Evaluates mobile application network security.
"""
import re
import zipfile
from pathlib import Path

from utils.logger import get_logger
from utils.analysis_helpers import proximity_search, is_benign_url

logger = get_logger("NetworkAnalysis")


class NetworkAnalyzer:
    """Analyzes network security posture of mobile applications."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.findings = []
        self.network_config = {}

    def _extract_evidence_details(self, content: str, match_start: int, match_end: int, filename: str) -> dict:
        """
        Extract structured evidence details from a pattern match:
        file path, line number, class name, method name, matched string, and a code snippet.
        """
        if not content:
            return {}
        try:
            line_no = content[:match_start].count("\n") + 1
            matched = content[match_start:match_end]
            
            # Snippet extraction
            lines = content.split("\n")
            line_idx = line_no - 1
            start_idx = max(0, line_idx - 2)
            end_idx = min(len(lines), line_idx + 3)
            
            snippet_lines = []
            for idx in range(start_idx, end_idx):
                prefix = "--> " if idx == line_idx else "    "
                snippet_lines.append(f"{idx+1:4d} | {prefix}{lines[idx]}")
            code_snippet = "\n".join(snippet_lines)
            
            # Class name extraction
            content_before = content[:match_start]
            class_matches = list(re.finditer(r"\bclass\s+(\w+)", content_before))
            class_name = class_matches[-1].group(1) if class_matches else "N/A"
            
            # Method name extraction (supports Java/Kotlin/Swift)
            method_matches = list(re.finditer(r"\b(?:public|protected|private|static|\s)+\s+[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*(?:\{|throws)", content_before))
            fun_matches = list(re.finditer(r"\bfun\s+(\w+)", content_before))
            swift_matches = list(re.finditer(r"\bfunc\s+(\w+)", content_before))
            
            method_name = "N/A"
            if swift_matches and (not fun_matches or swift_matches[-1].start() > fun_matches[-1].start()):
                if not method_matches or swift_matches[-1].start() > method_matches[-1].start():
                    method_name = swift_matches[-1].group(1)
            elif fun_matches and (not method_matches or fun_matches[-1].start() > method_matches[-1].start()):
                method_name = fun_matches[-1].group(1)
            elif method_matches:
                method_name = method_matches[-1].group(1)
                
            return {
                "file_path": filename,
                "line_number": line_no,
                "class_name": class_name,
                "method_name": method_name,
                "matched_string": matched,
                "code_snippet": code_snippet
            }
        except Exception as e:
            logger.error(f"Error extracting evidence details: {e}")
            return {}

    def analyze(self) -> dict:
        """Run network security analysis."""
        logger.info(f"Starting network analysis: {self.file_path.name}")

        self._check_cleartext_traffic()
        self._check_tls_implementation()
        self._check_certificate_pinning()
        self._check_certificate_validation()
        self._check_network_security_config()
        self._check_http_urls()
        self._check_websocket_security()

        return {
            "network_config": self.network_config,
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

    def _check_cleartext_traffic(self):
        """Check for cleartext (HTTP) traffic allowance."""
        strings = self._get_strings()

        # Android: Check for usesCleartextTraffic
        for item in strings:
            if "usesCleartextTraffic" in item["content"]:
                if re.search(r'(?i)android:usesCleartextTraffic\s*=\s*["\']true["\']', item["content"]):
                    self.findings.append({
                        "title": "Cleartext Traffic Allowed",
                        "severity": "high",
                        "description": "android:usesCleartextTraffic is set to true. "
                                       "The application allows unencrypted HTTP traffic.",
                        "category": "network",
                        "owasp": "M5",
                        "cwe": "CWE-319",
                        "evidence": "usesCleartextTraffic=true in manifest",
                    })
                    self.network_config["cleartext_allowed"] = True

        # iOS: Check ATS
        for item in strings:
            if re.search(r'NSAllowsArbitraryLoads.*?(?:true|<true\s*/?>)', item["content"], re.IGNORECASE | re.DOTALL):
                self.findings.append({
                    "title": "iOS ATS Disabled",
                    "severity": "high",
                    "description": "App Transport Security is disabled, allowing insecure connections.",
                    "category": "network",
                    "owasp": "M5",
                    "cwe": "CWE-319",
                    "evidence": "NSAllowsArbitraryLoads in Info.plist",
                })

    def _check_tls_implementation(self):
        """Check TLS implementation quality."""
        insecure_tls_patterns = {
            "SSLv3 Usage": (r"(?i)SSLv3|SSL\.3", "SSLv3 is deprecated and vulnerable to POODLE"),
            "TLS 1.0": (r"(?i)TLSv1(?:\.0)?(?!\.\d)", "TLS 1.0 is deprecated"),
            "TLS 1.1": (r"(?i)TLSv1\.1", "TLS 1.1 is deprecated"),
            "Weak Cipher Suite": (
                r"\b(RC4|3DES|DESede|_EXPORT_|TLS_.*EXPORT|SSL_.*EXPORT|DH_anon)\b",
                "Weak cipher suites are vulnerable to attacks",
            ),
        }

        for item in self._get_strings():
            # Skip compiled binary resource files (images, binary drawables)
            if item["file"].startswith("res/") and not item["file"].endswith((".xml", ".json", ".txt")):
                continue
            for issue_name, (pattern, desc) in insecure_tls_patterns.items():
                matches = list(re.finditer(pattern, item["content"], re.IGNORECASE if issue_name != "Weak Cipher Suite" else 0))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(item["content"], m.start(), m.end(), item["file"])
                    finding = {
                        "title": f"Insecure TLS: {issue_name}",
                        "severity": "high",
                        "description": desc,
                        "category": "network",
                        "owasp": "M5",
                        "cwe": "CWE-326",
                        "evidence": f"Found in {item['file']}: {m.group(0)[:60]}",
                    }
                    finding.update(details)
                    self.findings.append(finding)
            # Separate check for MD5 only when near cipher/SSL/TLS context
            md5_cipher_matches = proximity_search(
                item["content"],
                r'\bMD5\b',
                r'(?i)(cipher|ssl|tls|suite)',
                max_line_distance=3,
                file_name=item.get('file', '')
            )
            if md5_cipher_matches:
                md5_hits = list(re.finditer(r'\bMD5\b', item["content"], re.IGNORECASE))
                if not md5_hits:
                    continue
                m = md5_hits[0]
                details = self._extract_evidence_details(item["content"], m.start(), m.end(), item["file"])
                finding = {
                    "title": "Insecure TLS: MD5 Cipher Usage",
                    "severity": "high",
                    "description": "MD5 is used in a cipher/SSL/TLS context, which is weak and vulnerable to collision attacks.",
                    "category": "network",
                    "owasp": "M5",
                    "cwe": "CWE-326",
                    "evidence": f"Found in {item['file']}",
                }
                finding.update(details)
                self.findings.append(finding)

    def _check_certificate_pinning(self):
        """Check for certificate pinning implementation."""
        pinning_patterns = [
            r"(?i)CertificatePinner",
            r"(?i)certificate.?pinn",
            r"(?i)public.?key.?pinn",
            r"(?i)ssl.?pinn",
            r"(?i)TrustKit",
            r"(?i)pin-sha256",
        ]

        found = False
        for item in self._get_strings():
            for pattern in pinning_patterns:
                if re.search(pattern, item["content"]):
                    found = True
                    self.network_config["cert_pinning"] = True
                    break
            if found:
                break

        if not found:
            self.findings.append({
                "title": "No Certificate Pinning",
                "severity": "info",
                "confidence": "low",
                "description": "Certificate pinning is not implemented. The application is vulnerable "
                               "to man-in-the-middle attacks using forged certificates.",
                "category": "network",
                "owasp": "M5",
                "cwe": "CWE-295",
                "evidence": "No certificate pinning patterns detected",
            })
            self.network_config["cert_pinning"] = False

    def _check_certificate_validation(self):
        """Check for disabled certificate validation."""
        bypass_patterns = {
            "TrustAll TrustManager": (
                r"(?i)X509TrustManager.*checkServerTrusted",
                "Custom TrustManager may accept all certificates",
            ),
            "HostnameVerifier Bypass": (
                r"(?i)ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier",
                "Hostname verification is disabled",
            ),
            "SSL Error Bypass": (
                r"(?i)onReceivedSslError.*proceed",
                "SSL errors are being ignored in WebView",
            ),
            "Verify None": (
                r"(?i)verify\s*=\s*False|CERT_NONE",
                "Certificate verification is disabled",
            ),
        }

        for item in self._get_strings():
            for issue_name, (pattern, desc) in bypass_patterns.items():
                matches = list(re.finditer(pattern, item["content"]))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(item["content"], m.start(), m.end(), item["file"])
                    finding = {
                        "title": f"Certificate Validation Bypass: {issue_name}",
                        "severity": "critical",
                        "description": desc + ". This makes the application vulnerable to MITM attacks.",
                        "category": "network",
                        "owasp": "M5",
                        "cwe": "CWE-295",
                        "evidence": f"Found in {item['file']}: {m.group(0)[:60]}",
                    }
                    finding.update(details)
                    self.findings.append(finding)

    def _check_network_security_config(self):
        """Check Android Network Security Configuration."""
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                # Look for network_security_config.xml
                for name in zf.namelist():
                    if "network_security_config" in name.lower():
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        self.network_config["has_network_security_config"] = True

                        # Check for cleartext permission using regex to verify explicit true value
                        if "cleartextTrafficPermitted" in content:
                            if re.search(r'cleartextTrafficPermitted\s*=\s*["\']true["\']', content, re.IGNORECASE):
                                self.findings.append({
                                    "title": "Cleartext Traffic in Network Security Config",
                                    "severity": "high",
                                    "description": "Network Security Config permits cleartext traffic.",
                                    "category": "network",
                                    "owasp": "M5",
                                    "cwe": "CWE-319",
                                    "evidence": f"cleartextTrafficPermitted=true in {name}",
                                })

                        # Check for trust-anchors allowing user certs
                        if "user" in content and "trust-anchors" in content:
                            self.findings.append({
                                "title": "User Certificates Trusted",
                                "severity": "medium",
                                "description": "Network Security Config trusts user-installed certificates. "
                                               "This allows interception with proxy tools.",
                                "category": "network",
                                "owasp": "M5",
                                "cwe": "CWE-295",
                                "evidence": f"User certificates in trust-anchors in {name}",
                            })
                        return

            if self.platform == "android":
                self.network_config["has_network_security_config"] = False
                self.findings.append({
                    "title": "No Network Security Configuration",
                    "severity": "medium",
                    "description": "No network_security_config.xml found. The application relies "
                                   "on default network security settings.",
                    "category": "network",
                    "owasp": "M5",
                    "cwe": "CWE-693",
                    "evidence": "network_security_config.xml not found in APK",
                })
        except Exception as e:
            logger.error(f"Network config check error: {e}")

    def _check_http_urls(self):
        """Check for HTTP (non-HTTPS) URLs."""
        http_count = 0
        http_urls = []

        for item in self._get_strings():
            urls = re.findall(r'http://[^\s<>"\']+', item["content"])
            for url in urls:
                # Skip common non-sensitive URLs
                if is_benign_url(url):
                    continue
                http_count += 1
                if len(http_urls) < 10:
                    http_urls.append(url)

        if http_count > 0:
            self.findings.append({
                "title": f"Insecure HTTP URLs ({http_count} found)",
                "severity": "medium",
                "description": f"Found {http_count} HTTP (non-HTTPS) URLs. Data transmitted over "
                               "HTTP is vulnerable to interception.",
                "category": "network",
                "owasp": "M5",
                "cwe": "CWE-319",
                "evidence": f"Sample URLs: {', '.join(http_urls[:5])}",
            })

    def _check_websocket_security(self):
        """Check WebSocket security."""
        for item in self._get_strings():
            matches = list(re.finditer(r"ws://(?!localhost|127\.0\.0\.1)", item["content"]))
            if matches:
                m = matches[0]
                details = self._extract_evidence_details(item["content"], m.start(), m.end(), item["file"])
                finding = {
                    "title": "Insecure WebSocket (ws://)",
                    "severity": "medium",
                    "description": "Unencrypted WebSocket connection found. Use wss:// for secure WebSocket.",
                    "category": "network",
                    "owasp": "M5",
                    "cwe": "CWE-319",
                    "evidence": f"ws:// URL in {item['file']}",
                }
                finding.update(details)
                self.findings.append(finding)
                return

