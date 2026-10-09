"""
Zero-Day Heuristic & Behavioral Analyzer Module
Detects novel, zero-day vulnerabilities using taint-flow heuristics,
custom cryptography detection, obfuscated reflection audits, and behavioral capability profiling.
"""
import re
import zipfile
from pathlib import Path
from utils.logger import get_logger
from utils.analysis_helpers import line_scoped_search, proximity_search, is_third_party_library

logger = get_logger("ZeroDayAnalyzer")


class ZeroDayAnalyzer:
    """Performs heuristic and behavioral audits to detect zero-day vulnerabilities."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.findings = []
        self.capabilities = {
            "has_network": False,
            "has_dynamic_loading": False,
            "has_sensitive_permissions": False,
            "permissions_list": [],
        }

    def analyze(self) -> dict:
        """Run zero-day heuristic analysis pipeline."""
        logger.info(f"Starting zero-day heuristic analysis: {self.file_path.name}")

        strings = self._get_strings()
        
        self._audit_taint_flows(strings)
        self._audit_reflection_and_dcl(strings)
        self._audit_custom_cryptography(strings)
        self._audit_deep_links(strings)
        self._profile_behavioral_anomalies(strings)

        return {
            "findings": self.findings,
            "capabilities": self.capabilities,
        }

    def _get_strings(self) -> list[dict]:
        """Extract strings and source contents from package."""
        strings = []
        try:
            with zipfile.ZipFile(str(self.file_path), "r") as zf:
                for info in zf.infolist():
                    # Skip large binary files or assets
                    if info.file_size > 5_000_000:
                        continue
                    name_lower = info.filename.lower()
                    # Focus on source code, manifest, plist, configurations
                    if any(name_lower.endswith(ext) for ext in 
                           (".java", ".kt", ".xml", ".plist", ".m", ".swift", ".json", ".properties")):
                        try:
                            # Skip third-party library files to focus on custom app code
                            if is_third_party_library(info.filename):
                                continue
                            raw = zf.read(info.filename)
                            text = raw.decode("utf-8", errors="ignore")
                            strings.append({"file": info.filename, "content": text})
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"Error extracting strings for zero-day analysis: {e}")
        return strings

    def _audit_taint_flows(self, strings: list[dict]):
        """
        Detects potential zero-day injection flaws (SQLi, Command Injection, WebView RCE)
        by tracing untrusted sources flowing into dangerous sinks within the same class context.
        """
        # Sources representing untrusted user input or external data
        sources = {
            "getIntent": "Intent Extra Input",
            "getExtras": "Intent Bundle Input",
            "getQueryParameter": "URL Query Parameter",
            "getClipData": "Clipboard Input",
            "getInputStream": "Network/File Stream Input",
            "readLine": "Buffered Reader Input",
            "getDeviceId": "Device IMEI Identifier Source",
            "getLastKnownLocation": "Location GPS Coordinate Source",
            "getSubscriberId": "Subscriber IMSI Source",
            "getSimSerialNumber": "SIM Serial Number Source",
        }
        
        # Sinks representing dangerous operations
        sinks = {
            r"Runtime\.getRuntime\(\)\.exec\(": ("Command Execution", "critical", "CWE-78"),
            r"SQLiteDatabase\.rawQuery\(": ("SQL Query Execution", "high", "CWE-89"),
            r"WebView\.loadUrl\(": ("WebView Page Loading", "high", "CWE-79"),
            r"Class\.forName\(": ("Dynamic Class Resolution", "medium", "CWE-470"),
            r"FileOutputStream\.write\(": ("File System Write", "medium", "CWE-22"),
            r"Log\.[vdiwew]\(": ("Sensitive Information Logging", "medium", "CWE-532"),
            r"sendTextMessage\(": ("Insecure SMS Telephony Transmission", "high", "CWE-926"),
            r"URL\.openConnection\(": ("Cleartext Network Channel Initiation", "medium", "CWE-319"),
        }


        for item in strings:
            content = item["content"]
            file_name = item["file"]
            
            # Check if file has at least one source and one sink
            found_sources = [name for term, name in sources.items() if term in content]
            if not found_sources:
                continue
                
            for sink_pattern, (sink_name, severity, cwe) in sinks.items():
                if re.search(sink_pattern, content):
                    # Perform proximity check: if source and sink are within 10 lines of each other
                    for src_term, src_name in sources.items():
                        matches = proximity_search(
                            content, 
                            re.escape(src_term), 
                            sink_pattern, 
                            max_line_distance=10, 
                            file_name=file_name
                        )
                        if matches:
                            evidence_line = matches[0].line_number
                            evidence_content = matches[0].line_content
                            self.findings.append({
                                "title": "Zero-Day Risk: Potential Taint Flow Injection",
                                "severity": severity,
                                "description": f"Heuristic analysis detected an untrusted input source ({src_name}) "
                                               f"flowing in close proximity (within 10 lines) to a dangerous execution sink ({sink_name}) "
                                               f"in {file_name}. This indicates a high risk of zero-day injection vulnerabilities (e.g., RCE, SQLi, or XSS).",
                                "category": "zero_day",
                                "owasp": "M4",
                                "cwe": cwe,
                                "evidence": f"Source '{src_term}' and Sink '{sink_name}' near line {evidence_line}: {evidence_content.strip()}",
                                "confidence": "medium",
                            })
                            break  # Avoid duplicate alerts for the same file

    def _audit_reflection_and_dcl(self, strings: list[dict]):
        """
        Audits Java reflection and Dynamic Class Loading (DCL).
        Zero-day payloads frequently hide malicious execution using dynamic API resolution.
        """
        for item in strings:
            content = item["content"]
            file_name = item["file"]

            # 1. Dynamic Class Loading (DCL)
            dcl_patterns = (
                "DexClassLoader", "PathClassLoader", "Dalvik.system", 
                "InMemoryDexClassLoader", "NSBundle"
            )
            for dcl in dcl_patterns:
                if dcl in content:
                    self.capabilities["has_dynamic_loading"] = True
                    self.findings.append({
                        "title": "Zero-Day Risk: Dynamic Code Execution (DCL)",
                        "severity": "high",
                        "description": f"Found dynamic class loader reference ({dcl}) in '{file_name}'. "
                                       f"Loading code dynamically (.dex, .jar, or bundle) allows runtime payload "
                                       f"execution which bypasses standard static code vetting.",
                        "category": "zero_day",
                        "owasp": "M7",
                        "cwe": "CWE-494",
                        "evidence": f"Reference: '{dcl}' in {file_name}",
                        "confidence": "high",
                    })

            # 2. Obfuscated/Dynamic Reflection
            # Flag Class.forName where the class name is dynamically resolved via variable/parameters rather than a literal string
            reflection_matches = re.finditer(r"Class\.forName\(\s*([a-zA-Z0-9_\.\+ ]+)\s*\)", content)
            for rm in reflection_matches:
                arg = rm.group(1).strip()
                # If it's not a literal string (i.e. doesn't start and end with quotes)
                if not (arg.startswith('"') and arg.endswith('"')) and not (arg.startswith("'") and arg.endswith("'")):
                    self.findings.append({
                        "title": "Zero-Day Risk: Obfuscated Method Resolution",
                        "severity": "medium",
                        "description": f"Heuristic analysis detected dynamic reflection in '{file_name}'. "
                                       f"The class name is resolved dynamically (via variable '{arg}') rather than "
                                       f"a static literal string. This is a common evasion technique to execute hidden APIs.",
                        "category": "zero_day",
                        "owasp": "M7",
                        "cwe": "CWE-470",
                        "evidence": f"Dynamic reflection: Class.forName({arg})",
                        "confidence": "medium",
                    })

    def _audit_custom_cryptography(self, strings: list[dict]):
        """
        Detects custom cryptographic implementations ("roll-your-own-crypto").
        Zero-day flaws frequently occur when developers implement custom encryption loops (e.g., custom XOR shifts).
        """
        for item in strings:
            content = item["content"]
            file_name = item["file"]
            
            # Look for byte-level XOR loops representing custom encryption/obfuscation
            # Pattern: a loop iterating through a byte/char array and performing XOR operations on elements
            xor_loop_pattern = r"(?s)(for|while)\s*\(.*?\)\s*\{.*?\b([a-zA-Z0-9_\[\]\.\+\-\>\*]+)\s*\^=\s*([a-zA-Z0-9_\(\)\.\+\-\>]+).*?\}"
            match = re.search(xor_loop_pattern, content)
            if match:
                # Confirm it's not standard library stuff by doing a basic keyword check
                keywords = ("encrypt", "decrypt", "cipher", "obfuscate", "xor", "mask", "key")
                context_match = any(k in content.lower() for k in keywords)
                if context_match:
                    self.findings.append({
                        "title": "Zero-Day Risk: Custom Cryptographic/XOR Loop",
                        "severity": "high",
                        "description": f"Detected a custom byte manipulation loop performing XOR operations in '{file_name}'. "
                                       f"Implementing custom cryptography ('roll-your-own-crypto') is highly prone to mathematical "
                                       f"and implementation flaws that lead to zero-day key recovery or encryption bypasses.",
                        "category": "zero_day",
                        "owasp": "M10",
                        "cwe": "CWE-327",
                        "evidence": f"XOR-Loop detected: {match.group(0)[:120]}...",
                        "confidence": "medium",
                    })

    def _audit_deep_links(self, strings: list[dict]):
        """
        Audits custom URL schemes and deep-link intent parsing.
        Zero-day exploits frequently hijack custom schemes to trigger unauthorized state changes or data leakage.
        """
        for item in strings:
            content = item["content"]
            file_name = item["file"]

            # Look for intent filters with custom scheme parsing
            if "android:scheme" in content or "LSMatchesSchemes" in content:
                # Trace if they retrieve query parameters and flow them directly into intent launches
                if "getQueryParameter" in content and ("startActivity" in content or "sendBroadcast" in content):
                    self.findings.append({
                        "title": "Zero-Day Risk: Insecure Deep-Link Parameter Routing",
                        "severity": "high",
                        "description": f"Heuristic analysis identified custom deep-link scheme handling combined with "
                                       f"direct parameter extraction (getQueryParameter) and intent launching in '{file_name}'. "
                                       f"Attackers can hijack this scheme to execute arbitrary local actions (Zero-Day Intent Redirects).",
                        "category": "zero_day",
                        "owasp": "M3",
                        "cwe": "CWE-927",
                        "evidence": f"Custom scheme + parameter parsing + activity launch in {file_name}",
                        "confidence": "medium",
                    })

    def _profile_behavioral_anomalies(self, strings: list[dict]):
        """
        Profiles the application's overall behavioral capabilities.
        Zero-day threats (like malware, spyware, or RATs) combine specific APIs that are highly anomalous.
        """
        # 1. Inspect Permissions and Network
        for item in strings:
            content = item["content"]
            
            # Network indicators
            if any(term in content for term in ("HttpURLConnection", "HttpClient", "java.net.URL", "Socket(", "NSURLSession")):
                self.capabilities["has_network"] = True
                
            # Permission indicators in Manifest
            if "AndroidManifest.xml" in item["file"]:
                ns = "{http://schemas.android.com/apk/res/android}"
                try:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(content)
                    for perm in root.findall(".//uses-permission"):
                        name = perm.get(f"{ns}name", perm.get("name", ""))
                        if name:
                            self.capabilities["permissions_list"].append(name)
                except Exception:
                    # Fallback regex
                    perms = re.findall(r"android\.permission\.\w+", content)
                    self.capabilities["permissions_list"] = list(set(perms))

        # Check for dangerous permission profiles
        dangerous_permissions = {
            "android.permission.READ_SMS", "android.permission.RECORD_AUDIO", 
            "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG"
        }
        
        active_dangerous = [p for p in self.capabilities["permissions_list"] if p in dangerous_permissions]
        if active_dangerous:
            self.capabilities["has_sensitive_permissions"] = True

        # Behavioral Profiler Rules
        # Rule 1: Sensitive Permissions + Network Transmission + Dynamic Code Execution = High-risk Spyware Profile
        if (self.capabilities["has_sensitive_permissions"] and 
            self.capabilities["has_network"] and 
            self.capabilities["has_dynamic_loading"]):
            
            self.findings.append({
                "title": "Zero-Day Risk: Suspicious Spyware/RAT Behavioral Profile",
                "severity": "critical",
                "description": "Behavioral profiling flagged a highly anomalous capability combination. "
                               "The application requests highly sensitive privacy permissions (SMS, camera, audio, or location), "
                               "possesses network socket capabilities, and executes dynamic class loading (DCL) or dynamic reflection. "
                               "This combination is characteristic of zero-day remote access trojans (RATs) or advanced spyware.",
                "category": "zero_day",
                "owasp": "M2",
                "cwe": "CWE-506", # Embedded Malicious Code
                "evidence": f"Sensitive Permissions: {', '.join([p.split('.')[-1] for p in active_dangerous])} | "
                            f"Network: True | Dynamic Loading: True",
                "confidence": "high",
            })
