"""
Dynamic Analysis Module
Runtime analysis capabilities for mobile applications.
Attempts real Frida instrumentation when available, falls back to
static heuristic checks when no device/emulator is connected.
"""
import re
import zipfile
from pathlib import Path
from utils.logger import get_logger

logger = get_logger("DynamicAnalysis")

# Try to import Frida engine (optional dependency)
try:
    from modules.frida_engine import FridaInstrumenter
    FRIDA_ENGINE_AVAILABLE = True
except ImportError:
    FRIDA_ENGINE_AVAILABLE = False


class DynamicAnalyzer:
    def __init__(self, file_path: Path, package_name: str = None):
        self.file_path = Path(file_path) if not isinstance(file_path, Path) else file_path
        self.platform = "android" if self.file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.package_name = package_name or self.file_path.stem
        self.findings = []
        self.runtime_indicators = []
        self._cached_strings = None  # Cache to avoid redundant ZIP extraction

    def analyze(self) -> dict:
        logger.info(f"Starting dynamic analysis: {self.file_path.name}")

        # Phase 1: Try real Frida instrumentation
        frida_results = self._try_frida_instrumentation()

        # Phase 2: Static heuristic checks (always run as supplementary)
        self._check_runtime_secrets()
        self._check_ipc_security()
        self._check_deep_links()
        self._check_screen_capture()
        self._check_biometric_auth()
        self._check_runtime_protections()
        self._generate_frida_scripts()

        # Preserve instrumentation outcomes even when no runtime finding was
        # captured, so an install/compatibility failure appears in the report.
        if frida_results:
            self.runtime_indicators.extend(frida_results.get("hooks_log", []))

        # Merge Frida findings if any
        if frida_results and frida_results.get("findings"):
            frida_count = len(frida_results["findings"])
            logger.info(f"Frida instrumentation captured {frida_count} runtime findings")
            self.findings.extend(frida_results["findings"])

        return {"runtime_indicators": self.runtime_indicators, "findings": self.findings}

    def _try_frida_instrumentation(self) -> dict:
        """Attempt real Frida-based dynamic analysis.
        
        Returns instrumentation results dict, or empty dict if unavailable.
        """
        if not FRIDA_ENGINE_AVAILABLE:
            logger.info("Frida engine module not available -- using static heuristics only")
            return {}

        if self.platform != "android":
            logger.info("Frida instrumentation is only supported for Android APKs")
            return {}

        try:
            instrumenter = FridaInstrumenter(self.file_path, self.package_name)
            if not instrumenter.is_available():
                logger.info("No ADB device/emulator detected -- skipping Frida instrumentation")
                return {}

            logger.info("ADB device detected -- launching Frida instrumentation...")
            results = instrumenter.instrument(timeout=60)
            return results

        except Exception as e:
            logger.warning(f"Frida instrumentation failed (falling back to static): {e}")
            return {}

    def _get_strings(self):
        """Extract text content from APK entries (cached to avoid redundant reads)."""
        if self._cached_strings is not None:
            return self._cached_strings
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
        self._cached_strings = strings
        return strings

    def _check_runtime_secrets(self):
        for item in self._get_strings():
            if re.search(r"(?i)EncryptedSharedPreferences|SecureStorage", item["content"]):
                self.runtime_indicators.append({"type": "SecureStorage", "file": item["file"]})

    def _check_ipc_security(self):
        """Check for unprotected broadcasts across ALL files (no premature return)."""
        found_any = False
        for item in self._get_strings():
            matches = re.finditer(r"(?i)sendBroadcast(?!.*permission)", item["content"])
            for m in matches:
                line_start = item["content"].rfind('\n', 0, m.start()) + 1
                line_end = item["content"].find('\n', m.end())
                if line_end == -1:
                    line_end = len(item["content"])
                line = item["content"][line_start:line_end]
                if "LocalBroadcastManager" in line:
                    continue
                if not found_any:
                    self.findings.append({
                        "title": "Unprotected Broadcast", "severity": "medium",
                        "description": "Broadcast sent without permission restriction.",
                        "category": "dynamic", "owasp": "M1", "cwe": "CWE-927",
                        "evidence": f"Found in {item['file']}"})
                    found_any = True

    def _check_deep_links(self):
        """Check for custom URL schemes across ALL files (no premature return)."""
        found_any = False
        for item in self._get_strings():
            if re.search(r"(?i)android:scheme\s*=\s*['\"](?!https?)", item["content"]):
                if not found_any:
                    self.findings.append({
                        "title": "Custom URL Scheme", "severity": "medium",
                        "description": "Custom URL schemes can be hijacked.",
                        "category": "dynamic", "owasp": "M1", "cwe": "CWE-939",
                        "evidence": f"Deep link in {item['file']}"})
                    found_any = True

    def _check_screen_capture(self):
        found = any(re.search(r"(?i)FLAG_SECURE", i["content"]) for i in self._get_strings())
        if not found:
            self.findings.append({
                "title": "No Screen Capture Protection", "severity": "info",
                "description": "FLAG_SECURE not used. Screenshots possible.",
                "category": "dynamic", "owasp": "M2", "cwe": "CWE-200",
                "evidence": "FLAG_SECURE not found",
                "confidence": "low"})

    def _check_biometric_auth(self):
        """Check biometric auth across ALL files - don't stop after first match."""
        has_biometric = False
        has_crypto_object = False
        biometric_file = ""
        for item in self._get_strings():
            if re.search(r"(?i)BiometricPrompt|FingerprintManager", item["content"]):
                has_biometric = True
                if not biometric_file:
                    biometric_file = item["file"]
            if re.search(r"(?i)CryptoObject", item["content"]):
                has_crypto_object = True
        if has_biometric and not has_crypto_object:
            self.findings.append({
                "title": "Weak Biometric Auth", "severity": "medium",
                "description": "Biometric auth without CryptoObject.",
                "category": "dynamic", "owasp": "M4", "cwe": "CWE-287",
                "evidence": f"Found in {biometric_file}"})

    def _check_runtime_protections(self):
        all_content = " ".join(i["content"] for i in self._get_strings())
        missing = []
        if not re.search(r'(?i)frida', all_content): missing.append('Frida')
        if not re.search(r'(?i)xposed', all_content): missing.append('Xposed')
        if not re.search(r'(?i)magisk', all_content): missing.append('Magisk')
        if missing:
            self.findings.append({
                "title": "Missing Runtime Tamper Detection",
                "severity": "info",
                "description": f"No detection for: {', '.join(missing)}. Consider adding runtime integrity checks for sensitive applications.",
                "category": "dynamic",
                "owasp": "M8",
                "cwe": "CWE-693",
                "evidence": "No tamper detection patterns found in application code",
                "confidence": "low",
            })

    def _generate_frida_scripts(self):
        self.runtime_indicators.append({
            "type": "frida_scripts",
            "scripts": {
                "ssl_bypass": "Java.perform(function(){var SSLContext=Java.use('javax.net.ssl.SSLContext');SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom').implementation=function(km,tm,sr){console.log('[*] SSL Context.init() intercepted');this.init(km,tm,sr);};});",
                "root_bypass": "Java.perform(function(){var RootBeer=Java.use('com.scottyab.rootbeer.RootBeer');RootBeer.isRooted.implementation=function(){console.log('[*] Root check bypassed');return false;};});",
                "crypto_monitor": "Java.perform(function(){var Cipher=Java.use('javax.crypto.Cipher');Cipher.init.overload('int','java.security.Key').implementation=function(mode,key){console.log('[*] Cipher.init: mode='+mode+' algo='+this.getAlgorithm());return this.init(mode,key);};});",
            }
        })
