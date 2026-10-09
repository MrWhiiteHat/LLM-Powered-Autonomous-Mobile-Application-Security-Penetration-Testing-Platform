"""
Reverse Engineering Module
Extracts intelligence from mobile application binaries.
"""
import re
import json
import zipfile
from pathlib import Path

from utils.analysis_helpers import is_high_entropy_secret
from typing import Optional

from utils.logger import get_logger

logger = get_logger("ReverseEngineering")


class ReverseEngineer:
    """Extracts information from mobile application packages."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.backend_urls = []
        self.api_endpoints = []
        self.tokens = []
        self.credentials = []
        self.config_files = []
        self.interesting_files = []
        self.findings = []

    def analyze(self) -> dict:
        """Run reverse engineering analysis."""
        logger.info(f"Starting reverse engineering: {self.file_path.name}")

        self._enumerate_files()
        self._extract_configs()
        self._extract_backend_urls()
        self._extract_tokens_credentials()
        self._check_code_obfuscation()
        self._check_binary_protections()

        return {
            "backend_urls": self.backend_urls,
            "api_endpoints": self.api_endpoints,
            "tokens": self.tokens,
            "credentials": self.credentials,
            "config_files": self.config_files,
            "interesting_files": self.interesting_files,
            "findings": self.findings,
        }

    def _enumerate_files(self):
        """List and categorize files in the package."""
        interesting_extensions = {
            ".json", ".xml", ".plist", ".db", ".sqlite", ".sqlite3",
            ".properties", ".yml", ".yaml", ".cfg", ".conf", ".ini",
            ".key", ".pem", ".cert", ".crt", ".p12", ".pfx", ".jks",
            ".so", ".dylib",
        }

        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    ext = Path(info.filename).suffix.lower()
                    if ext in interesting_extensions:
                        self.interesting_files.append({
                            "path": info.filename,
                            "size": info.file_size,
                            "type": ext,
                        })
                    # Check for certificate/key files
                    if ext in (".key", ".pem", ".cert", ".crt", ".p12", ".pfx", ".jks"):
                        if ext in (".p12", ".pfx", ".jks", ".key"):
                            # Private key containers — always high severity
                            self.findings.append({
                                "title": f"Certificate/Key File Found: {info.filename}",
                                "severity": "high",
                                "description": f"Found {ext} file bundled in the application. "
                                               "This may contain private keys or certificates.",
                                "category": "reverse_engineering",
                                "owasp": "M1",
                                "cwe": "CWE-321",
                                "evidence": info.filename,
                            })
                        else:
                            # .pem, .cert, .crt — check if it contains a private key
                            try:
                                cert_content = zf.read(info.filename).decode("utf-8", errors="ignore")
                            except Exception:
                                cert_content = ""
                            if "BEGIN PRIVATE KEY" in cert_content or "BEGIN RSA PRIVATE KEY" in cert_content:
                                self.findings.append({
                                    "title": f"Private Key File Found: {info.filename}",
                                    "severity": "high",
                                    "description": f"Found {ext} file containing a private key "
                                                   "bundled in the application.",
                                    "category": "reverse_engineering",
                                    "owasp": "M1",
                                    "cwe": "CWE-321",
                                    "evidence": info.filename,
                                })
                            else:
                                self.findings.append({
                                    "title": f"Public Certificate Found: {info.filename}",
                                    "severity": "info",
                                    "confidence": "low",
                                    "description": f"Found {ext} public certificate bundled in the "
                                                   "application. No private key material detected.",
                                    "category": "reverse_engineering",
                                    "owasp": "M1",
                                    "cwe": "CWE-321",
                                    "evidence": info.filename,
                                })
        except Exception as e:
            logger.error(f"File enumeration error: {e}")

    def _extract_configs(self):
        """Extract and analyze configuration files."""
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    name_lower = info.filename.lower()
                    if any(name_lower.endswith(ext) for ext in
                           (".json", ".properties", ".yml", ".yaml", ".cfg", ".conf")):
                        try:
                            content = zf.read(info.filename).decode("utf-8", errors="ignore")
                            if len(content) < 50000:  # Skip very large files
                                self.config_files.append({
                                    "path": info.filename,
                                    "content_preview": content[:2000],
                                })

                                # Check for sensitive config
                                self._check_sensitive_config(info.filename, content)
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"Config extraction error: {e}")

    def _check_sensitive_config(self, filename: str, content: str):
        """Check config files for sensitive data."""
        sensitive_keys = [
            "password", "secret", "api_key", "apikey", "auth_token",
            "access_token", "private_key", "db_password", "database_url",
            "smtp_password", "client_secret", "signing_key",
        ]

        content_lower = content.lower()
        for key in sensitive_keys:
            if key in content_lower:
                # Look for a key=value pattern to extract the actual value
                kv_pattern = re.compile(
                    re.escape(key) + r'\s*(?:=|:|=>)\s*["\']?([^"\'\s,;}{\]\)]+)',
                    re.IGNORECASE,
                )
                kv_match = kv_pattern.search(content)
                if not kv_match:
                    continue  # No key-value pair found, skip
                value = kv_match.group(1)
                if not is_high_entropy_secret(value, min_entropy=3.2, min_length=8):
                    continue  # Low entropy or placeholder value, skip
                self.findings.append({
                    "title": f"Sensitive Config: {key} in {filename}",
                    "severity": "high",
                    "description": f"Configuration file '{filename}' contains '{key}' which may expose sensitive data.",
                    "category": "reverse_engineering",
                    "owasp": "M1",
                    "cwe": "CWE-312",
                    "evidence": f"Key '{key}' found in {filename}",
                })

    def _extract_backend_urls(self):
        """Extract backend URLs and API endpoints."""
        url_patterns = [
            r'https?://(?:api|backend|server|auth|gateway|service)[.\w\-]+(?:/[\w\-./]*)?',
            r'https?://[\w\-]+\.(?:herokuapp|azurewebsites|amazonaws|firebaseio|appspot)\.(?:com|net)(?:/[\w\-./]*)?',
        ]

        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    if info.file_size > 10_000_000:  # Skip files > 10MB
                        continue
                    try:
                        raw = zf.read(info.filename)
                        text = raw.decode("utf-8", errors="ignore")

                        for pattern in url_patterns:
                            matches = re.findall(pattern, text)
                            for url in matches:
                                if url not in [u["url"] for u in self.backend_urls]:
                                    self.backend_urls.append({
                                        "url": url,
                                        "source": info.filename,
                                    })

                        # API path patterns
                        api_paths = re.findall(r'["\']/(?:api|v[12]|auth|graphql)/[\w\-./]+["\']', text)
                        for path in api_paths:
                            self.api_endpoints.append({
                                "path": path if isinstance(path, str) else str(path),
                                "source": info.filename,
                            })
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"URL extraction error: {e}")

    def _extract_tokens_credentials(self):
        """Extract embedded tokens and credentials."""
        token_patterns = {
            "Bearer Token": r"[Bb]earer\s+([a-zA-Z0-9\-._~+/]+=*)",
            "Basic Auth": r"[Bb]asic\s+([a-zA-Z0-9+/]+=+)",
            "JWT": r"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
        }

        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    if info.file_size > 5_000_000:
                        continue
                    try:
                        raw = zf.read(info.filename)
                        # Extract ASCII strings
                        strings = re.findall(rb"[\x20-\x7e]{10,}", raw)
                        combined = " ".join(s.decode("ascii", errors="ignore") for s in strings)

                        for token_type, pattern in token_patterns.items():
                            matches = re.findall(pattern, combined)
                            for match in matches[:3]:
                                if not is_high_entropy_secret(match, min_entropy=3.0, min_length=10):
                                    continue
                                masked = match[:10] + "***" if len(match) > 10 else "***"
                                self.tokens.append({
                                    "type": token_type,
                                    "masked_value": masked,
                                    "source": info.filename,
                                })
                    except Exception:
                        pass
                        
            # After token extraction loop, convert self.tokens to findings
            for token in self.tokens:
                self.findings.append({
                    "title": f"Embedded {token['type']}",
                    "severity": "high",
                    "description": f"{token['type']} found embedded in application code.",
                    "category": "reverse_engineering",
                    "owasp": "M1",
                    "cwe": "CWE-798",
                    "evidence": f"Token ({token['type']}) found in {token['source']}: {token['masked_value']}",
                    "file_path": token['source'],
                    "confidence": "high",
                })

        except Exception as e:
            logger.error(f"Token extraction error: {e}")

    def _check_code_obfuscation(self):
        """Check if code is obfuscated."""
        if self.platform != "android":
            return

        obfuscation_indicators = 0
        short_class_names = 0
        total_classes = 0

        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    if info.filename.endswith(".dex"):
                        try:
                            raw = zf.read(info.filename)
                            # Count short class names (sign of ProGuard/R8)
                            classes = re.findall(rb"L([a-z]{1,2}/[a-z]{1,2});", raw)
                            short_class_names += len(classes)
                            total_classes += len(re.findall(rb"L[\w/$]+;", raw))
                        except Exception:
                            pass
        except Exception:
            pass

        if total_classes > 0:
            obfuscation_ratio = short_class_names / total_classes
            if obfuscation_ratio < 0.1:
                self.findings.append({
                    "title": "Code Not Obfuscated",
                    "severity": "medium",
                    "description": "The application code does not appear to be obfuscated. "
                                   "This makes reverse engineering significantly easier.",
                    "category": "protection",
                    "owasp": "M7",
                    "cwe": "CWE-693",
                    "evidence": f"Obfuscation ratio: {obfuscation_ratio:.2%} "
                                f"({short_class_names}/{total_classes} short names)",
                })

    def _check_binary_protections(self):
        """Check for binary protection mechanisms."""
        protection_checks = {
            "anti_tamper": [r"(?i)tamper.?detect", r"(?i)integrity.?check", r"(?i)signature.?verif"],
            "anti_debug": [r"(?i)anti.?debug", r"(?i)isDebugger", r"(?i)ptrace"],
            "anti_emulator": [r"(?i)isEmulator", r"(?i)emulator.?detect", r"(?i)goldfish", r"(?i)generic.*sdk"],
        }

        found_protections = set()

        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    if info.file_size > 5_000_000:
                        continue
                    try:
                        raw = zf.read(info.filename)
                        text = raw.decode("utf-8", errors="ignore")

                        for prot_name, patterns in protection_checks.items():
                            for pattern in patterns:
                                if re.search(pattern, text):
                                    found_protections.add(prot_name)
                    except Exception:
                        pass
        except Exception:
            pass

        missing = set(protection_checks.keys()) - found_protections
        if missing:
            missing_display = [p.replace("_", " ").title() for p in sorted(missing)]
            self.findings.append({
                "title": f"Missing Binary Protections: {', '.join(missing_display)}",
                "severity": "low",
                "confidence": "low",
                "description": f"The following binary protection mechanisms were not detected: "
                               f"{', '.join(missing_display)}. The application may be "
                               f"vulnerable to runtime attacks.",
                "category": "protection",
                "owasp": "M7",
                "cwe": "CWE-693",
                "evidence": f"Missing: {', '.join(missing_display)}",
            })
