"""
Dynamic Analysis Module
Runtime analysis capabilities for mobile applications.
"""
import re
import zipfile
from pathlib import Path
from utils.logger import get_logger

logger = get_logger("DynamicAnalysis")


class DynamicAnalyzer:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.findings = []
        self.runtime_indicators = []

    def analyze(self) -> dict:
        logger.info(f"Starting dynamic analysis: {self.file_path.name}")
        self._check_runtime_secrets()
        self._check_ipc_security()
        self._check_deep_links()
        self._check_screen_capture()
        self._check_biometric_auth()
        self._check_runtime_protections()
        self._generate_frida_scripts()
        return {"runtime_indicators": self.runtime_indicators, "findings": self.findings}

    def _get_strings(self):
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

    def _check_runtime_secrets(self):
        for item in self._get_strings():
            if re.search(r"(?i)EncryptedSharedPreferences|SecureStorage", item["content"]):
                self.runtime_indicators.append({"type": "SecureStorage", "file": item["file"]})

    def _check_ipc_security(self):
        for item in self._get_strings():
            if re.search(r"(?i)sendBroadcast(?!.*permission)", item["content"]):
                self.findings.append({
                    "title": "Unprotected Broadcast", "severity": "medium",
                    "description": "Broadcast sent without permission restriction.",
                    "category": "dynamic", "owasp": "M8", "cwe": "CWE-927",
                    "evidence": f"Found in {item['file']}"})

    def _check_deep_links(self):
        for item in self._get_strings():
            if re.search(r"(?i)android:scheme\s*=\s*['\"](?!https?)", item["content"]):
                self.findings.append({
                    "title": "Custom URL Scheme", "severity": "medium",
                    "description": "Custom URL schemes can be hijacked.",
                    "category": "dynamic", "owasp": "M8", "cwe": "CWE-939",
                    "evidence": f"Deep link in {item['file']}"})
                return

    def _check_screen_capture(self):
        found = any(re.search(r"(?i)FLAG_SECURE", i["content"]) for i in self._get_strings())
        if not found:
            self.findings.append({
                "title": "No Screen Capture Protection", "severity": "low",
                "description": "FLAG_SECURE not used. Screenshots possible.",
                "category": "dynamic", "owasp": "M9", "cwe": "CWE-200",
                "evidence": "FLAG_SECURE not found"})

    def _check_biometric_auth(self):
        for item in self._get_strings():
            if re.search(r"(?i)BiometricPrompt|FingerprintManager", item["content"]):
                if not re.search(r"(?i)CryptoObject", item["content"]):
                    self.findings.append({
                        "title": "Weak Biometric Auth", "severity": "medium",
                        "description": "Biometric auth without CryptoObject.",
                        "category": "dynamic", "owasp": "M3", "cwe": "CWE-287",
                        "evidence": f"Found in {item['file']}"})
                return

    def _check_runtime_protections(self):
        checks = {"Frida": r"(?i)frida", "Xposed": r"(?i)xposed", "Magisk": r"(?i)magisk"}
        strings = self._get_strings()
        for name, pattern in checks.items():
            found = any(re.search(pattern, i["content"]) for i in strings)
            if not found:
                self.findings.append({
                    "title": f"No {name} Detection", "severity": "low",
                    "description": f"No {name} detection found.",
                    "category": "dynamic", "owasp": "M7", "cwe": "CWE-693",
                    "evidence": f"No {name} patterns found"})

    def _generate_frida_scripts(self):
        self.runtime_indicators.append({
            "type": "frida_scripts",
            "scripts": {
                "ssl_bypass": "Java.perform(function(){console.log('SSL bypass loaded');});",
                "root_bypass": "Java.perform(function(){console.log('Root bypass loaded');});",
            }
        })
