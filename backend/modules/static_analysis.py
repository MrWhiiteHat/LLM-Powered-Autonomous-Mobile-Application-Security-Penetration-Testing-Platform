"""
Static Analysis Module
Analyzes APK/IPA files for security vulnerabilities without execution.
"""
import re
import zipfile
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from utils.logger import get_logger
from utils.analysis_helpers import (proximity_search, is_placeholder_value, is_high_entropy_secret)

logger = get_logger("StaticAnalysis")


class StaticAnalyzer:
    """Performs static security analysis on mobile applications."""

    def __init__(self, file_path: Path, decompiled_dir: Path = None):
        self.file_path = file_path
        self.decompiled_dir = decompiled_dir
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.findings = []
        self.manifest_data = {}
        self.extracted_strings = []
        self.permissions = []
        self.components = {"activities": [], "services": [], "receivers": [], "providers": []}
        self.api_endpoints = []
        self.secrets = []

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
            self._check_dynamic_code_loading()
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
        """Extract readable strings from APK.
        
        If decompiled Java/Kotlin sources are available (via jadx),
        those are loaded first for higher-fidelity analysis with accurate
        line numbers and class/method context. The raw DEX string extraction
        is still performed as a supplementary pass.
        """
        # Phase 1: Load decompiled sources (high fidelity)
        if self.decompiled_dir and self.decompiled_dir.exists():
            decompiled_count = 0
            try:
                for java_file in self.decompiled_dir.rglob("*.java"):
                    try:
                        content = java_file.read_text(encoding="utf-8", errors="ignore")
                        rel_path = str(java_file.relative_to(self.decompiled_dir))
                        self.extracted_strings.append({"file": rel_path, "content": content})
                        decompiled_count += 1
                    except Exception:
                        pass
                for kt_file in self.decompiled_dir.rglob("*.kt"):
                    try:
                        content = kt_file.read_text(encoding="utf-8", errors="ignore")
                        rel_path = str(kt_file.relative_to(self.decompiled_dir))
                        self.extracted_strings.append({"file": rel_path, "content": content})
                        decompiled_count += 1
                    except Exception:
                        pass
                if decompiled_count:
                    logger.info(f"Loaded {decompiled_count} decompiled source files for analysis")
            except Exception as e:
                logger.warning(f"Error loading decompiled sources: {e}")
        
        # Phase 2: Standard ZIP extraction (configs + fallback binary strings)
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for name in zf.namelist():
                    if name.endswith((".xml", ".json", ".properties", ".yml", ".yaml", ".txt")):
                        try:
                            content = zf.read(name).decode("utf-8", errors="ignore")
                            self.extracted_strings.append({"file": name, "content": content})
                        except Exception:
                            pass
                    elif name.endswith((".java", ".kt")):
                        # Only extract from ZIP if we don't have decompiled sources
                        if not (self.decompiled_dir and self.decompiled_dir.exists()):
                            try:
                                content = zf.read(name).decode("utf-8", errors="ignore")
                                self.extracted_strings.append({"file": name, "content": content})
                            except Exception:
                                pass
                    elif name.endswith((".dex", ".so")):
                        # Only extract raw DEX strings if we don't have decompiled sources
                        if not (self.decompiled_dir and self.decompiled_dir.exists()):
                            try:
                                info = zf.getinfo(name)
                                if info.file_size > 50 * 1024 * 1024:
                                    continue
                                raw = zf.read(name)
                                strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
                                if strings:
                                    decoded_strings = [s.decode("ascii", errors="ignore") for s in strings]
                                    self.extracted_strings.append({
                                        "file": name,
                                        "content": "\n".join(decoded_strings),
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

    def _get_aapt_path(self) -> str:
        """Resolve the path to the aapt executable, checking common paths first."""
        import os
        from shutil import which
        aapt = which("aapt")
        if aapt:
            return aapt
        
        user_profile = os.environ.get("USERPROFILE", str(Path.home()))
        sdk_path = os.path.join(user_profile, "AppData", "Local", "Android", "Sdk")
        bt_path = os.path.join(sdk_path, "build-tools")
        if os.path.exists(bt_path):
            try:
                versions = [d for d in os.listdir(bt_path) if os.path.isdir(os.path.join(bt_path, d))]
                if versions:
                    versions.sort()
                    latest = versions[-1]
                    aapt_exe = os.path.join(bt_path, latest, "aapt.exe")
                    if os.path.exists(aapt_exe):
                        return aapt_exe
            except Exception:
                pass
        return "aapt"

    def _parse_android_manifest(self):
        """Parse AndroidManifest.xml from APK."""
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_raw = zf.read("AndroidManifest.xml")
                    # Plain XML — try to parse as text first
                    try:
                        manifest_text = manifest_raw.decode("utf-8", errors="ignore")
                        root = ET.fromstring(manifest_text)
                        self._process_manifest_xml(root)
                    except ET.ParseError:
                        # Binary XML: parse via aapt dump xmltree
                        logger.info("Binary AndroidManifest.xml detected — invoking aapt dump xmltree")
                        parsed_via_aapt = False
                        aapt_path = self._get_aapt_path()
                        try:
                            res = subprocess.run(
                                [aapt_path, "dump", "xmltree", str(self.file_path), "AndroidManifest.xml"],
                                capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=15
                            )
                            if res.returncode == 0 and res.stdout:
                                self._parse_manifest_aapt_xmltree(res.stdout)
                                parsed_via_aapt = True
                                logger.info(f"Successfully parsed binary manifest via aapt: pkg={self.manifest_data.get('package')}, perms={len(self.permissions)}")
                        except Exception as e:
                            logger.warning(f"aapt dump xmltree execution failed: {e}")

                        if not parsed_via_aapt:
                            logger.warning("Falling back to raw string extraction for manifest")
                            self._parse_manifest_strings(manifest_raw)
                            # Try to resolve package name via aapt badging
                            try:
                                res = subprocess.run(
                                    [aapt_path, "dump", "badging", str(self.file_path)],
                                    capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=15
                                )
                                if res.returncode == 0:
                                    m_pkg = re.search(r"package:\s+name='([^']+)'", res.stdout)
                                    if m_pkg:
                                        self.manifest_data["package"] = m_pkg.group(1)
                            except Exception:
                                pass
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
            permission = activity.get(f"{ns}permission", activity.get("permission", ""))
            self.components["activities"].append({"name": name, "exported": exported, "permission": permission})

        # Services
        for service in root.findall(".//service"):
            name = service.get(f"{ns}name", service.get("name", ""))
            exported = service.get(f"{ns}exported", service.get("exported", ""))
            permission = service.get(f"{ns}permission", service.get("permission", ""))
            self.components["services"].append({"name": name, "exported": exported, "permission": permission})

        # Receivers
        for receiver in root.findall(".//receiver"):
            name = receiver.get(f"{ns}name", receiver.get("name", ""))
            exported = receiver.get(f"{ns}exported", receiver.get("exported", ""))
            permission = receiver.get(f"{ns}permission", receiver.get("permission", ""))
            self.components["receivers"].append({"name": name, "exported": exported, "permission": permission})

        # Content Providers
        for provider in root.findall(".//provider"):
            name = provider.get(f"{ns}name", provider.get("name", ""))
            exported = provider.get(f"{ns}exported", provider.get("exported", ""))
            permission = provider.get(f"{ns}permission", provider.get("permission", ""))
            self.components["providers"].append({"name": name, "exported": exported, "permission": permission})

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

    def _parse_manifest_aapt_xmltree(self, xmltree_output: str):
        """Parse AAPT xmltree output into permissions, components, and manifest_data."""
        curr_elem = None
        curr_comp = None

        for line in xmltree_output.splitlines():
            stripped = line.strip()
            if stripped.startswith("E: "):
                tag = stripped.split()[1]
                curr_elem = tag
                if tag in ("activity", "service", "receiver", "provider"):
                    comp_type = "activities" if tag == "activity" else tag + "s"
                    curr_comp = {"name": "", "exported": "false", "permission": ""}
                    self.components[comp_type].append(curr_comp)
                else:
                    if tag not in ("intent-filter", "action", "category", "data"):
                        curr_comp = None
            elif stripped.startswith("A: "):
                attr_line = stripped[3:]
                m_attr = re.match(r"([a-zA-Z0-9:_]+)(?:\([^)]+\))?=(.*)", attr_line)
                if m_attr:
                    aname = m_attr.group(1)
                    raw_val = m_attr.group(2).strip()
                    val = ""
                    m_raw = re.search(r'\(Raw:\s*"([^"]*)"\)', raw_val)
                    if m_raw:
                        val = m_raw.group(1)
                    elif "0xffffffff" in raw_val or '"true"' in raw_val.lower():
                        val = "true"
                    elif "0x0" in raw_val or '"false"' in raw_val.lower():
                        val = "false"
                    elif raw_val.startswith('"') and raw_val.endswith('"'):
                        val = raw_val[1:-1]

                    if aname == "package":
                        self.manifest_data["package"] = val
                    elif aname == "android:name":
                        if curr_elem == "uses-permission" and val:
                            if val not in self.permissions:
                                self.permissions.append(val)
                        elif curr_comp is not None and not curr_comp["name"]:
                            curr_comp["name"] = val
                    elif aname == "android:exported" and curr_comp is not None:
                        curr_comp["exported"] = val
                    elif aname == "android:permission" and curr_comp is not None:
                        curr_comp["permission"] = val
                    elif aname == "android:debuggable":
                        self.manifest_data["debuggable"] = val
                    elif aname == "android:allowBackup":
                        self.manifest_data["allowBackup"] = val
                    elif aname == "android:usesCleartextTraffic":
                        self.manifest_data["usesCleartextTraffic"] = val
                    elif aname == "android:networkSecurityConfig":
                        self.manifest_data["networkSecurityConfig"] = val

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
            "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
            "AWS Secret Key": r"(?i)\baws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
            "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "Firebase URL": r"https://[\w-]+\.firebaseio\.com",
            "Firebase API Key": r"(?i)firebase(.{0,20})?['\"][0-9a-zA-Z]{39}['\"]",
            "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
            "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]",
            "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "Bearer Token": r"(?i)\bbearer\s+[a-zA-Z0-9\-._~+/]{20,}\b=*",
            "JWT Token": r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
            "Slack Token": r"\bxox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24,}\b",
            "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b",
            "SendGrid API Key": r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b",
            "Stripe Key": r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b",
            "Twilio Key": r"\bSK[0-9a-fA-F]{32}\b",
            "Database URL": r"(?i)(mongodb|mysql|postgres|redis)://[^\s'\"]+",
        }

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            # High-confidence specific patterns
            high_confidence_secrets = {
                "AWS Access Key", "Google API Key", "GitHub Token",
                "Stripe Key", "Twilio Key",
            }
            # Generic key=value patterns
            generic_secrets = {"Generic API Key", "Generic Secret"}
            for secret_name, pattern in secret_patterns.items():
                matches = list(re.finditer(pattern, content))
                if matches:
                    for m in matches[:3]:  # Limit to 3 per pattern per file
                        match_str = m.group(0)
                        # Skip placeholder/template values for all secrets
                        if is_placeholder_value(match_str):
                            continue
                        # Skip placeholder/template values
                        if secret_name in generic_secrets:
                            val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                            # Skip low-entropy values or placeholders
                            if not is_high_entropy_secret(val, min_entropy=3.2, min_length=8):
                                continue
                        # Mask the secret
                        masked = match_str[:8] + "***" + match_str[-4:] if len(match_str) > 12 else "***"
                        # Determine confidence level
                        if secret_name in high_confidence_secrets:
                            confidence = "high"
                        elif secret_name in generic_secrets:
                            confidence = "medium"
                        else:
                            confidence = "high"
                        self.secrets.append({
                            "type": secret_name,
                            "file": item.get("file", "unknown"),
                            "masked_value": masked,
                        })
                        finding = {
                            "title": f"Hardcoded {secret_name}",
                            "severity": "high",
                            "description": f"Found {secret_name} in {item.get('file', 'unknown')}",
                            "category": "secrets",
                            "owasp": "M1",
                            "cwe": "CWE-798",
                            "evidence": f"Pattern match in {item.get('file', 'unknown')}: {masked}",
                            "confidence": confidence,
                        }
                        details = self._extract_evidence_details(content, m.start(), m.end(), item.get('file', 'unknown'))
                        finding.update(details)
                        self.findings.append(finding)

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
                        "severity": "info",
                        "description": f"Debug logging found in {item.get('file', 'unknown')}",
                        "category": "configuration",
                        "owasp": "M8",
                        "cwe": "CWE-215",
                        "evidence": f"Debug pattern in {item.get('file', 'unknown')}",
                        "confidence": "low",
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
                    # Downgrade severity if component has a permission attribute
                    has_permission = bool(comp.get("permission"))
                    severity = "info" if has_permission else "medium"
                    comp_name_clean = "Activity" if comp_type == "activities" else comp_type[:-1].title()
                    finding = {
                        "title": f"Exported {comp_name_clean}: {comp.get('name', 'unknown')}",
                        "severity": severity,
                        "description": f"The {comp_name_clean.lower()} '{comp.get('name')}' is exported and accessible "
                                       f"to other applications. Verify it has proper access controls.",
                        "category": "components",
                        "owasp": "M8",
                        "cwe": "CWE-926",
                        "evidence": f"android:exported=\"true\" on {comp.get('name')}",
                    }
                    if has_permission:
                        finding["confidence"] = "low"
                    self.findings.append(finding)

    def _check_insecure_crypto(self):
        """Detect insecure cryptographic implementations strictly."""
        insecure_patterns = {
            "ECB Mode": (r"(?i)AES/ECB", "ECB mode does not provide semantic security"),
            "DES Encryption": (r"(?i)DES(?:ede)?/", "DES is deprecated and weak"),
            "MD5 Hashing": (r"(?i)MessageDigest\.getInstance\(['\"]MD5", "MD5 is cryptographically broken"),
            "SHA-1 Hashing": (r"(?i)MessageDigest\.getInstance\(['\"]SHA-?1", "SHA-1 is deprecated"),
            "Static IV": (r"(?i)IvParameterSpec\(['\"]", "Using static IV is insecure"),
            "Hardcoded Salt": (r"(?i)(salt|SALT)\s*=\s*['\"]", "Hardcoded salt weakens hashing"),
            "Insecure Hostname Verifier": (r"(?i)verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;\s*\}", "Custom HostnameVerifier always returns true, disabling SSL/TLS hostname validation and exposing the application to Man-in-the-Middle (MitM) attacks"),
            "Insecure TrustManager": (r"(?i)checkServerTrusted\s*\(\s*X509Certificate\s*\[\s*\]\s+\w+\s*,\s*String\s+\w+\s*\)\s*\{\s*\}", "TrustManager checkServerTrusted implementation is empty, trusting all certificates and exposing the application to Man-in-the-Middle (MitM) attacks")
        }

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue

            # For java.util.Random - only flag if near security context
            random_matches = proximity_search(content, r'java\.util\.Random', 
                                               r'(?i)(encrypt|password|token|key|hash|salt|nonce|iv|cipher|secret|credential)',
                                               max_line_distance=5, file_name=item.get('file', ''))
            if random_matches:
                self.findings.append({
                    "title": "Insecure Cryptography: Weak Random",
                    "severity": "high",
                    "description": "java.util.Random is not cryptographically secure",
                    "category": "cryptography",
                    "owasp": "M10",
                    "cwe": "CWE-327",
                    "evidence": f"Found in {item.get('file', 'unknown')}",
                })

            for vuln_name, (pattern, desc) in insecure_patterns.items():
                matches = list(re.finditer(pattern, content))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(content, m.start(), m.end(), item.get('file', 'unknown'))
                    finding = {
                        "title": f"Insecure Cryptography: {vuln_name}",
                        "severity": "high",
                        "description": desc,
                        "category": "cryptography",
                        "owasp": "M10",
                        "cwe": "CWE-327",
                        "evidence": f"Found in {item.get('file', 'unknown')}: {m.group(0)[:60]}",
                    }
                    finding.update(details)
                    self.findings.append(finding)

    def _check_webview_security(self):
        """Check for WebView security issues strictly."""
        webview_patterns = {
            "JavaScript Enabled": (
                r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)",
                "JavaScript enabled in WebView — XSS risk",
                "medium"
            ),
            "File Access Enabled": (
                r"(?i)setAllowFileAccess\s*\(\s*true\s*\)",
                "File access enabled in WebView — local file read risk",
                "medium"
            ),
            "Universal File Access": (
                r"(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
                "Universal file access from file URLs — critical security risk allowing local file exfiltration",
                "high"
            ),
            "JavaScript Interface": (
                r"(?i)addJavascriptInterface",
                "JavaScript interface added — potential code injection from WebViews into native app context",
                "medium"
            ),
            "Web Contents Debugging Enabled": (
                r"(?i)setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",
                "Web contents debugging is enabled in production builds, allowing attackers to attach debuggers and inject malicious scripts",
                "high"
            ),
            "Save Password Enabled": (
                r"(?i)setSavePassword\s*\(\s*true\s*\)",
                "WebView is configured to save user passwords, potentially caching sensitive credentials in plaintext",
                "medium"
            )
        }

        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for vuln_name, (pattern, desc, severity) in webview_patterns.items():
                matches = list(re.finditer(pattern, content))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(content, m.start(), m.end(), item.get('file', 'unknown'))
                    finding = {
                        "title": f"WebView Security: {vuln_name}",
                        "severity": severity,
                        "description": desc,
                        "category": "webview",
                        "owasp": "M8",
                        "cwe": "CWE-749",
                        "evidence": f"Found in {item.get('file', 'unknown')}: {m.group(0)[:60]}",
                    }
                    finding.update(details)
                    self.findings.append(finding)

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
                matches = list(re.finditer(pattern, content))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(content, m.start(), m.end(), item.get('file', 'unknown'))
                    finding = {
                        "title": "Sensitive Data in Logs",
                        "severity": "medium",
                        "description": "Sensitive data (passwords, tokens, keys) logged via system logs",
                        "category": "logging",
                        "owasp": "M9",
                        "cwe": "CWE-532",
                        "evidence": f"Found in {item.get('file', 'unknown')}: {m.group(0)[:60]}",
                        "confidence": "medium",
                    }
                    finding.update(details)
                    self.findings.append(finding)
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
                "severity": "info",
                "description": "The application does not appear to implement root/jailbreak detection. "
                               "Running on a rooted device increases risk of data extraction.",
                "category": "protection",
                "owasp": "M7",
                "cwe": "CWE-919",
                "evidence": "No root detection patterns found in code",
                "confidence": "low",
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
                "severity": "info",
                "description": "No SSL/TLS certificate pinning implementation found. "
                               "The application may be vulnerable to man-in-the-middle attacks.",
                "category": "network",
                "owasp": "M5",
                "cwe": "CWE-295",
                "evidence": "No certificate pinning patterns found in code",
                "confidence": "low",
            })

    def _check_dynamic_code_loading(self):
        """Check for insecure dynamic class loading and reflection abuse (CWE-470 / MASTG-TEST-0052)."""
        dcl_patterns = [
            (r"(?i)DexClassLoader\s*\(", "Insecure Dynamic Class Loading: DexClassLoader", "Dynamic loading of executable bytecode via DexClassLoader from potentially untrusted or world-writable storage enables arbitrary code execution."),
            (r"(?i)PathClassLoader\s*\(", "Insecure Dynamic Class Loading: PathClassLoader", "Dynamic loading of Dalvik executable code via PathClassLoader."),
            (r"(?i)dalvik\.system\.(DexClassLoader|PathClassLoader)", "Dynamic Class Loader API Invocation", "Usage of Dalvik dynamic class loading API."),
            (r"(?i)Class\.forName\s*\(", "Dynamic Reflection: Class.forName Invocation", "Java dynamic reflection resolution via Class.forName. Unchecked reflection paths allow attacker-influenced class instantiation.")
        ]
        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            for pattern, title, desc in dcl_patterns:
                matches = list(re.finditer(pattern, content))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(content, m.start(), m.end(), item.get('file', 'unknown'))
                    finding = {
                        "title": title,
                        "severity": "high",
                        "description": desc,
                        "category": "code_execution",
                        "owasp": "M7",
                        "cwe": "CWE-470",
                        "evidence": f"Found in {item.get('file', 'unknown')}: {m.group(0)[:80]}",
                        "confidence": "high",
                    }
                    finding.update(details)
                    self.findings.append(finding)
                    break

    def _check_ats_settings(self):
        """Check iOS App Transport Security settings."""
        for item in self.extracted_strings:
            content = item.get("content", "")
            if not isinstance(content, str):
                continue
            matches = list(re.finditer(r"(?i)<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>|\bNSAllowsArbitraryLoads[\s:=]+true\b", content))
            if matches:
                m = matches[0]
                details = self._extract_evidence_details(content, m.start(), m.end(), item.get('file', 'unknown'))
                finding = {
                    "title": "App Transport Security Disabled",
                    "severity": "high",
                    "description": "NSAllowsArbitraryLoads is set to true, disabling ATS. "
                                   "This allows insecure HTTP connections.",
                    "category": "network",
                    "owasp": "M5",
                    "cwe": "CWE-319",
                    "evidence": "NSAllowsArbitraryLoads=true in Info.plist",
                }
                finding.update(details)
                self.findings.append(finding)
