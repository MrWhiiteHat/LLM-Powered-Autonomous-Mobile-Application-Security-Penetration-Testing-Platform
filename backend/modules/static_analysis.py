"""
Static Analysis Module
Analyzes APK/IPA files for security vulnerabilities without execution.
"""
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("StaticAnalysis")


class StaticAnalyzer:
    """Performs static security analysis on mobile applications."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.findings = []
        self.manifest_data = {}
        self.extracted_strings = []
        self.permissions = []
        self.components = {"activities": [], "services": [], "receivers": [], "providers": []}
        self.api_endpoints = []
        self.secrets = []

    def analyze(self) -> dict:
        """Run full static analysis pipeline."""
        logger.info(f"Starting static analysis: {self.file_path.name}")

        if self.platform == "android":
            self._analyze_android()
        else:
            self._analyze_ios()

        return {
            "platform": self.platform,
            "permissions": self.permissions,
            "components": self.components,
            "api_endpoints": self.api_endpoints,
            "secrets": self.secrets,
            "findings": self.findings,
            "manifest": self.manifest_data,
        }

    def _analyze_android(self):
        """Android-specific static analysis."""
        try:
            self._extract_strings_from_apk()
            self._parse_android_manifest()
            self._check_permissions()
            self._detect_hardcoded_secrets()
            self._detect_api_endpoints()
            self._check_debug_flags()
            self._check_backup_flag()
            self._check_exported_components()
            self._check_insecure_crypto()
            self._check_webview_security()
            self._check_logging()
            self._check_root_detection()
            self._check_ssl_pinning_code()
        except Exception as e:
            logger.error(f"Android analysis error: {e}")
            self.findings.append({
                "title": "Analysis Error",
                "severity": "info",
                "description": f"Error during analysis: {str(e)}",
                "category": "analysis",
            })

    def _analyze_ios(self):
        """iOS-specific static analysis."""
        try:
            self._extract_strings_from_ipa()
            self._detect_hardcoded_secrets()
            self._detect_api_endpoints()
            self._check_ats_settings()
            self._check_insecure_crypto()
        except Exception as e:
            logger.error(f"iOS analysis error: {e}")
            self.findings.append({
                "title": "Analysis Error",
                "severity": "info",
                "description": f"Error during analysis: {str(e)}",
                "category": "analysis",
            })

    def _extract_strings_from_apk(self):
        """Extract readable strings from APK."""
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for name in zf.namelist():
                    if name.endswith((".xml", ".json", ".properties", ".yml", ".yaml", ".txt")):
                        try:
                            content = zf.read(name).decode("utf-8", errors="ignore")
                            self.extracted_strings.append({"file": name, "content": content})
                        except Exception:
                            pass
                    elif name.endswith((".dex", ".so")):
                        try:
                            raw = zf.read(name)
                            # Extract printable ASCII strings (min length 6)
                            strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
                            for s in strings:
                                self.extracted_strings.append({
                                    "file": name,
                                    "content": s.decode("ascii", errors="ignore"),
                                })
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"String extraction error: {e}")

    def _extract_strings_from_ipa(self):
        """Extract readable strings from IPA."""
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for name in zf.namelist():
                    if name.endswith((".plist", ".json", ".strings", ".xml")):
                        try:
                            content = zf.read(name).decode("utf-8", errors="ignore")
                            self.extracted_strings.append({"file": name, "content": content})
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"IPA string extraction error: {e}")

    def _parse_android_manifest(self):
        """Parse AndroidManifest.xml from APK."""
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_raw = zf.read("AndroidManifest.xml")
                    # Binary XML — try to parse as text first
                    try:
                        manifest_text = manifest_raw.decode("utf-8", errors="ignore")
                        root = ET.fromstring(manifest_text)
                        self._process_manifest_xml(root)
                    except ET.ParseError:
                        # Binary XML needs androguard or axmlprinter
                        logger.warning("Binary AndroidManifest.xml detected — using string extraction fallback")
                        self._parse_manifest_strings(manifest_raw)
        except Exception as e:
            logger.error(f"Manifest parsing error: {e}")

    def _process_manifest_xml(self, root):
        """Process parsed AndroidManifest.xml."""
        ns = "{http://schemas.android.com/apk/res/android}"

        # Package name
        self.manifest_data["package"] = root.get("package", "unknown")

        # Permissions
        for perm in root.findall(".//uses-permission"):
            name = perm.get(f"{ns}name", perm.get("name", ""))
            if name:
                self.permissions.append(name)

        # Activities
        for activity in root.findall(".//activity"):
            name = activity.get(f"{ns}name", activity.get("name", ""))
            exported = activity.get(f"{ns}exported", activity.get("exported", ""))
            self.components["activities"].append({"name": name, "exported": exported})

        # Services
        for service in root.findall(".//service"):
            name = service.get(f"{ns}name", service.get("name", ""))
            exported = service.get(f"{ns}exported", service.get("exported", ""))
            self.components["services"].append({"name": name, "exported": exported})

        # Receivers
        for receiver in root.findall(".//receiver"):
            name = receiver.get(f"{ns}name", receiver.get("name", ""))
            exported = receiver.get(f"{ns}exported", receiver.get("exported", ""))
            self.components["receivers"].append({"name": name, "exported": exported})

        # Content Providers
        for provider in root.findall(".//provider"):
            name = provider.get(f"{ns}name", provider.get("name", ""))
            exported = provider.get(f"{ns}exported", provider.get("exported", ""))
            self.components["providers"].append({"name": name, "exported": exported})

        # Application flags
        app = root.find(".//application")
        if app is not None:
            self.manifest_data["debuggable"] = app.get(f"{ns}debuggable", "false")
            self.manifest_data["allowBackup"] = app.get(f"{ns}allowBackup", "true")
            self.manifest_data["usesCleartextTraffic"] = app.get(
                f"{ns}usesCleartextTraffic", "false"
            )
            self.manifest_data["networkSecurityConfig"] = app.get(
                f"{ns}networkSecurityConfig", ""
            )

    def _parse_manifest_strings(self, raw_data: bytes):
        """Fallback: extract permission/component strings from binary manifest."""
        text = raw_data.decode("utf-8", errors="ignore")
        # Extract permission-like strings
        perms = re.findall(r"android\.permission\.\w+", text)
        self.permissions = list(set(perms))

        # Extract component-like strings
        activities = re.findall(r"\.(?:Activity|activity)\w*", text)
        self.components["activities"] = [{"name": a, "exported": "unknown"} for a in set(activities)]

    def _check_permissions(self):
        """Check for dangerous permissions."""
        dangerous_permissions = {
            "android.permission.READ_SMS": "Can read SMS messages — potential data leak",
            "android.permission.SEND_SMS": "Can send SMS — potential premium SMS fraud",
            "android.permission.READ_CONTACTS": "Can read contacts — privacy risk",
            "android.permission.READ_CALL_LOG": "Can read call history — privacy risk",
            "android.permission.CAMERA": "Camera access — potential surveillance",
            "android.permission.RECORD_AUDIO": "Microphone access — potential surveillance",
            "android.permission.ACCESS_FINE_LOCATION": "Fine GPS location — tracking risk",
            "android.permission.READ_EXTERNAL_STORAGE": "External storage read — data exposure risk",
            "android.permission.WRITE_EXTERNAL_STORAGE": "External storage write — data tampering risk",
            "android.permission.INSTALL_PACKAGES": "Can install packages — malware risk",
            "android.permission.READ_PHONE_STATE": "Device info access — fingerprinting risk",
            "android.permission.SYSTEM_ALERT_WINDOW": "Overlay windows — clickjacking risk",
            "android.permission.REQUEST_INSTALL_PACKAGES": "Can request package install",
            "android.permission.ACCESS_BACKGROUND_LOCATION": "Background location tracking",
        }

        for perm in self.permissions:
            if perm in dangerous_permissions:
                self.findings.append({
                    "title": f"Dangerous Permission: {perm.split('.')[-1]}",
                    "severity": "medium",
                    "description": dangerous_permissions[perm],
                    "category": "permissions",
                    "owasp": "M8",
                    "cwe": "CWE-250",
                    "evidence": perm,
                })

    def _detect_hardcoded_secrets(self):
        """Detect hardcoded API keys, tokens, and credentials."""
        secret_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Firebase URL": r"https://[\w-]+\.firebaseio\.com",
            "Firebase API Key": r"(?i)firebase(.{0,20})?['\"][0-9a-zA-Z]{39}['\"]",
            "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
            "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]",
            "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24,}",
            "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
            "Stripe Key": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
            "Twilio Key": r"SK[0-9a-fA-F]{32}",
            "Database URL": r"(?i)(mongodb|mysql|postgres|redis)://[^\s'\"]+",
        }

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for secret_name, pattern in secret_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches[:3]:  # Limit to 3 per pattern per file
                        match_str = match if isinstance(match, str) else str(match)
                        # Mask the secret
                        masked = match_str[:8] + "***" + match_str[-4:] if len(match_str) > 12 else "***"
                        self.secrets.append({
                            "type": secret_name,
                            "file": item.get("file", "unknown"),
                            "masked_value": masked,
                        })
                        self.findings.append({
                            "title": f"Hardcoded {secret_name}",
                            "severity": "high",
                            "description": f"Found {secret_name} in {item.get('file', 'unknown')}",
                            "category": "secrets",
                            "owasp": "M1",
                            "cwe": "CWE-798",
                            "evidence": f"Pattern match in {item.get('file', 'unknown')}: {masked}",
                        })

    def _detect_api_endpoints(self):
        """Extract API endpoints and URLs."""
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]{5,}'

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            urls = re.findall(url_pattern, content)
            for url in urls:
                # Filter out common non-API URLs
                skip_domains = ["schemas.android.com", "www.w3.org", "schemas.xmlsoap.org",
                                "ns.adobe.com", "purl.org", "apache.org", "google.com/schemas"]
                if not any(d in url for d in skip_domains):
                    self.api_endpoints.append({
                        "url": url,
                        "source_file": item.get("file", "unknown"),
                    })

        # Deduplicate
        seen = set()
        unique = []
        for ep in self.api_endpoints:
            if ep["url"] not in seen:
                seen.add(ep["url"])
                unique.append(ep)
        self.api_endpoints = unique

    def _check_debug_flags(self):
        """Check for debug mode enabled."""
        if self.manifest_data.get("debuggable") == "true":
            self.findings.append({
                "title": "Application Debuggable",
                "severity": "high",
                "description": "The application has android:debuggable=true set in AndroidManifest.xml. "
                               "This allows attackers to attach a debugger and inspect runtime data.",
                "category": "configuration",
                "owasp": "M8",
                "cwe": "CWE-215",
                "evidence": "android:debuggable=\"true\" in AndroidManifest.xml",
            })

        # Check for debug logging patterns in code
        debug_patterns = [
            r"(?i)Log\.(d|v|i|w|e)\s*\(",
            r"(?i)System\.out\.print",
            r"(?i)console\.log",
            r"(?i)BuildConfig\.DEBUG",
        ]
        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for pattern in debug_patterns:
                if re.search(pattern, content):
                    self.findings.append({
                        "title": "Debug Logging Detected",
                        "severity": "low",
                        "description": f"Debug logging found in {item.get('file', 'unknown')}",
                        "category": "configuration",
                        "owasp": "M8",
                        "cwe": "CWE-215",
                        "evidence": f"Debug pattern in {item.get('file', 'unknown')}",
                    })
                    break  # One finding per file

    def _check_backup_flag(self):
        """Check if backup is allowed."""
        if self.manifest_data.get("allowBackup") in ("true", ""):
            self.findings.append({
                "title": "Application Backup Allowed",
                "severity": "medium",
                "description": "android:allowBackup is true or not set. Application data can be backed up "
                               "via ADB, potentially exposing sensitive data.",
                "category": "configuration",
                "owasp": "M9",
                "cwe": "CWE-530",
                "evidence": "android:allowBackup not set to false in AndroidManifest.xml",
            })

    def _check_exported_components(self):
        """Check for exported components without proper protection."""
        for comp_type, comps in self.components.items():
            for comp in comps:
                if comp.get("exported") == "true":
                    self.findings.append({
                        "title": f"Exported {comp_type[:-1].title()}: {comp.get('name', 'unknown')}",
                        "severity": "medium",
                        "description": f"The {comp_type[:-1]} '{comp.get('name')}' is exported and accessible "
                                       f"to other applications. Verify it has proper access controls.",
                        "category": "components",
                        "owasp": "M8",
                        "cwe": "CWE-926",
                        "evidence": f"android:exported=\"true\" on {comp.get('name')}",
                    })

    def _check_insecure_crypto(self):
        """Detect insecure cryptographic implementations."""
        insecure_patterns = {
            "ECB Mode": (r"(?i)AES/ECB", "ECB mode does not provide semantic security"),
            "DES Encryption": (r"(?i)DES(?:ede)?/", "DES is deprecated and weak"),
            "MD5 Hashing": (r"(?i)MessageDigest\.getInstance\(['\"]MD5", "MD5 is cryptographically broken"),
            "SHA-1 Hashing": (r"(?i)MessageDigest\.getInstance\(['\"]SHA-?1", "SHA-1 is deprecated"),
            "Static IV": (r"(?i)IvParameterSpec\(['\"]", "Using static IV is insecure"),
            "Weak Random": (r"(?i)java\.util\.Random(?!\w)", "java.util.Random is not cryptographically secure"),
            "Hardcoded Salt": (r"(?i)(salt|SALT)\s*=\s*['\"]", "Hardcoded salt weakens hashing"),
        }

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for vuln_name, (pattern, desc) in insecure_patterns.items():
                if re.search(pattern, content):
                    self.findings.append({
                        "title": f"Insecure Cryptography: {vuln_name}",
                        "severity": "high",
                        "description": desc,
                        "category": "cryptography",
                        "owasp": "M10",
                        "cwe": "CWE-327",
                        "evidence": f"Found in {item.get('file', 'unknown')}",
                    })

    def _check_webview_security(self):
        """Check for WebView security issues."""
        webview_patterns = {
            "JavaScript Enabled": (
                r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)",
                "JavaScript enabled in WebView — XSS risk",
            ),
            "File Access Enabled": (
                r"(?i)setAllowFileAccess\s*\(\s*true\s*\)",
                "File access enabled in WebView — local file read risk",
            ),
            "Universal File Access": (
                r"(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
                "Universal file access from file URLs — critical security risk",
            ),
            "JavaScript Interface": (
                r"(?i)addJavascriptInterface",
                "JavaScript interface added — potential code injection",
            ),
        }

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for vuln_name, (pattern, desc) in webview_patterns.items():
                if re.search(pattern, content):
                    self.findings.append({
                        "title": f"WebView Security: {vuln_name}",
                        "severity": "medium",
                        "description": desc,
                        "category": "webview",
                        "owasp": "M8",
                        "cwe": "CWE-749",
                        "evidence": f"Found in {item.get('file', 'unknown')}",
                    })

    def _check_logging(self):
        """Check for sensitive data in logs."""
        sensitive_log_patterns = [
            r"(?i)Log\.\w+\(.*(?:password|secret|token|key|credential|session).*\)",
            r"(?i)print\(.*(?:password|secret|token|key|credential).*\)",
        ]

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for pattern in sensitive_log_patterns:
                if re.search(pattern, content):
                    self.findings.append({
                        "title": "Sensitive Data in Logs",
                        "severity": "medium",
                        "description": "Sensitive data (passwords, tokens, keys) may be logged",
                        "category": "logging",
                        "owasp": "M9",
                        "cwe": "CWE-532",
                        "evidence": f"Found in {item.get('file', 'unknown')}",
                    })
                    break

    def _check_root_detection(self):
        """Check for root/jailbreak detection."""
        root_indicators = [
            r"(?i)isRooted", r"(?i)isJailbroken", r"(?i)su\s+binary",
            r"(?i)RootBeer", r"(?i)SafetyNet", r"(?i)rootCheck",
            r"/system/xbin/su", r"/system/app/Superuser",
        ]

        found_root_check = False
        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for pattern in root_indicators:
                if re.search(pattern, content):
                    found_root_check = True
                    break
            if found_root_check:
                break

        if not found_root_check:
            self.findings.append({
                "title": "No Root/Jailbreak Detection",
                "severity": "medium",
                "description": "The application does not appear to implement root/jailbreak detection. "
                               "Running on a rooted device increases risk of data extraction.",
                "category": "protection",
                "owasp": "M7",
                "cwe": "CWE-919",
                "evidence": "No root detection patterns found in code",
            })

    def _check_ssl_pinning_code(self):
        """Check for SSL/TLS pinning implementation."""
        pinning_indicators = [
            r"(?i)CertificatePinner", r"(?i)certificate.?pinn",
            r"(?i)TrustManager", r"(?i)ssl.?pinn",
            r"(?i)OkHttpClient.*certificatePinner",
            r"(?i)network_security_config",
        ]

        found_pinning = False
        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for pattern in pinning_indicators:
                if re.search(pattern, content):
                    found_pinning = True
                    break
            if found_pinning:
                break

        if not found_pinning:
            self.findings.append({
                "title": "No Certificate Pinning Detected",
                "severity": "high",
                "description": "No SSL/TLS certificate pinning implementation found. "
                               "The application may be vulnerable to man-in-the-middle attacks.",
                "category": "network",
                "owasp": "M5",
                "cwe": "CWE-295",
                "evidence": "No certificate pinning patterns found in code",
            })

    def _check_ats_settings(self):
        """Check iOS App Transport Security settings."""
        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            if "NSAllowsArbitraryLoads" in content and "true" in content.lower():
                self.findings.append({
                    "title": "App Transport Security Disabled",
                    "severity": "high",
                    "description": "NSAllowsArbitraryLoads is set to true, disabling ATS. "
                                   "This allows insecure HTTP connections.",
                    "category": "network",
                    "owasp": "M5",
                    "cwe": "CWE-319",
                    "evidence": "NSAllowsArbitraryLoads=true in Info.plist",
                })
