"""
Storage Security Analysis Module
Checks for insecure data storage patterns in mobile applications.
"""
import re
import zipfile
from pathlib import Path

from utils.logger import get_logger
from utils.analysis_helpers import proximity_search

logger = get_logger("StorageAnalysis")


class StorageAnalyzer:
    """Analyzes mobile application storage security."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.platform = "android" if file_path.suffix.lower() in (".apk", ".xapk") else "ios"
        self.findings = []
        self.storage_issues = []

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
        """Run storage security analysis."""
        logger.info(f"Starting storage analysis: {self.file_path.name}")

        if self.platform == "android":
            self._check_shared_preferences()
            self._check_sqlite_usage()
            self._check_external_storage()
            self._check_keystore_usage()
            self._check_file_permissions()
            self._check_content_providers()
        else:
            self._check_ios_keychain()
            self._check_ios_plist_storage()
            self._check_ios_core_data()

        self._check_plaintext_storage()
        self._check_clipboard_usage()
        self._check_cache_storage()

        return {
            "storage_issues": self.storage_issues,
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

    def _check_shared_preferences(self):
        """Check for sensitive data in SharedPreferences."""
        # MODE_WORLD patterns are exact matches, check directly
        mode_patterns = {
            "MODE_WORLD_READABLE": r"MODE_WORLD_READABLE",
            "MODE_WORLD_WRITEABLE": r"MODE_WORLD_WRITEABLE",
        }

        for item in self._get_strings():
            for issue_name, pattern in mode_patterns.items():
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": f"Insecure Storage: {issue_name}",
                        "severity": "critical",
                        "description": f"{issue_name} detected in {item['file']}. "
                                       "Sensitive data should not be stored in SharedPreferences without encryption.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-312",
                        "evidence": f"Pattern found in {item['file']}",
                    })
                    self.storage_issues.append(issue_name)

        # Sensitive data patterns: use proximity_search to require both patterns within 3 lines
        sensitive_checks = {
            "Password in SharedPreferences": (
                r"(?i)(?:getSharedPreferences|edit\(\))",
                r"(?i)(?:password|passwd|pwd)",
            ),
            "Token in SharedPreferences": (
                r"(?i)(?:getSharedPreferences|putString)",
                r"(?i)(?:token|session|auth)",
            ),
            "Credentials in SharedPreferences": (
                r"(?i)(?:SharedPreferences|edit\(\))",
                r"(?i)(?:credential|username|login)",
            ),
        }

        for item in self._get_strings():
            for issue_name, (pattern_a, pattern_b) in sensitive_checks.items():
                matches = proximity_search(item["content"], pattern_a, pattern_b,
                                           max_line_distance=3, file_name=item.get('file', ''))
                if matches:
                    self.findings.append({
                        "title": f"Insecure Storage: {issue_name}",
                        "severity": "high",
                        "description": f"{issue_name} detected in {item['file']}. "
                                       "Sensitive data should not be stored in SharedPreferences without encryption.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-312",
                        "evidence": f"Pattern found in {item['file']}",
                    })
                    self.storage_issues.append(issue_name)

    def _check_sqlite_usage(self):
        """Check for insecure SQLite usage."""
        patterns = {
            "Unencrypted SQLite": r"(?i)SQLiteDatabase\.open|openOrCreateDatabase",
            "Raw SQL Query": r"(?i)rawQuery|execSQL",
            "SQL Injection Risk": r"(?i)rawQuery\s*\([^?]*\+",
        }

        for item in self._get_strings():
            for issue_name, pattern in patterns.items():
                if re.search(pattern, item["content"]):
                    severity = "high" if "Injection" in issue_name else "medium"
                    self.findings.append({
                        "title": f"SQLite Security: {issue_name}",
                        "severity": severity,
                        "description": f"{issue_name} detected. Consider using SQLCipher for "
                                       "encrypted databases and parameterized queries.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-311" if "Unencrypted" in issue_name else "CWE-89",
                        "evidence": f"Pattern found in {item['file']}",
                    })

    def _check_external_storage(self):
        """Check for data written to external storage."""
        patterns = [
            r"(?i)getExternalStorage",
            r"(?i)getExternalFilesDir",
            r"(?i)Environment\.getExternalStorageDirectory",
            r"(?i)WRITE_EXTERNAL_STORAGE",
        ]

        for item in self._get_strings():
            for pattern in patterns:
                matches = proximity_search(item["content"], pattern,
                                           r"(?i)(?:password|passwd|pwd|secret|token|credential|sensitive|private|personal)",
                                           max_line_distance=5, file_name=item.get('file', ''))
                if matches:
                    self.findings.append({
                        "title": "Data Written to External Storage",
                        "severity": "medium",
                        "description": "The application writes data to external storage which is "
                                       "accessible to all applications on the device.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-276",
                        "evidence": f"External storage access in {item['file']}",
                    })
                    break

    def _check_keystore_usage(self):
        """Check for proper Android Keystore usage."""
        keystore_patterns = [
            r"(?i)KeyStore\.getInstance",
            r"(?i)AndroidKeyStore",
            r"(?i)KeyGenParameterSpec",
        ]

        found = False
        for item in self._get_strings():
            for pattern in keystore_patterns:
                if re.search(pattern, item["content"]):
                    found = True
                    break
            if found:
                break

        if not found:
            self.findings.append({
                "title": "Android Keystore Not Used",
                "severity": "low",
                "confidence": "low",
                "description": "The application does not appear to use Android Keystore for "
                               "secure key storage. Cryptographic keys may be stored insecurely.",
                "category": "storage",
                "owasp": "M9",
                "cwe": "CWE-321",
                "evidence": "No Android Keystore usage patterns detected",
            })

    def _check_file_permissions(self):
        """Check for insecure file permissions."""
        patterns = {
            "World Readable File": r"(?i)MODE_WORLD_READABLE|openFileOutput.*[12]",
            "World Writable File": r"(?i)MODE_WORLD_WRITEABLE",
        }

        for item in self._get_strings():
            for issue_name, pattern in patterns.items():
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": f"Insecure File Permission: {issue_name}",
                        "severity": "high",
                        "description": f"{issue_name} — files are accessible to all apps on the device.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-276",
                        "evidence": f"Found in {item['file']}",
                    })

    def _check_content_providers(self):
        """Check for insecure content provider configurations."""
        patterns = [
            r"(?i)content://",
            r"(?i)ContentProvider",
            r"(?i)grantUriPermission",
        ]

        for item in self._get_strings():
            for pattern in patterns:
                if re.search(pattern, item["content"]):
                    # Check if provider has path-permission
                    if not re.search(r"(?i)path-permission|readPermission|writePermission",
                                     item["content"]):
                        self.findings.append({
                            "title": "Content Provider Without Access Control",
                            "severity": "medium",
                            "description": "Content provider may lack proper access controls.",
                            "category": "storage",
                            "owasp": "M9",
                            "cwe": "CWE-926",
                            "evidence": f"Content provider in {item['file']}",
                        })
                    break

    def _check_plaintext_storage(self):
        """Check for plaintext sensitive data storage."""
        patterns = {
            "Plaintext Password Storage": r"(?i)(save|store|write|put).*password.*(?:file|pref|db|storage)",
            "Plaintext Token Storage": r"(?i)(save|store|write|put).*(?:access.?token|refresh.?token|session).*(?:file|pref|db)",
            "Plaintext PII Storage": r"(?i)(save|store|write|put).*(?:ssn|social.?security|credit.?card|card.?number)",
        }

        for item in self._get_strings():
            # Skip raw binary files (DEX/SO) — cross-line regex matching on compiled bytecode
            # generates false positive matches for standard framework storage methods
            if item["file"].endswith((".dex", ".so")):
                continue
            for issue_name, pattern in patterns.items():
                matches = list(re.finditer(pattern, item["content"]))
                if matches:
                    m = matches[0]
                    details = self._extract_evidence_details(item["content"], m.start(), m.end(), item["file"])
                    finding = {
                        "title": issue_name,
                        "severity": "high",
                        "description": f"{issue_name} detected. Sensitive data must be encrypted before storage.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-312",
                        "evidence": f"Pattern found in {item['file']}",
                    }
                    finding.update(details)
                    self.findings.append(finding)

    def _check_clipboard_usage(self):
        """Check for sensitive data copied to clipboard."""
        patterns = [
            r"(?i)ClipboardManager",
            r"(?i)setPrimaryClip",
            r"(?i)ClipData\.newPlainText",
            r"(?i)UIPasteboard",
        ]

        for item in self._get_strings():
            for pattern in patterns:
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": "Clipboard Usage Detected",
                        "severity": "info",
                        "confidence": "low",
                        "description": "The application uses the clipboard. Sensitive data copied to "
                                       "clipboard can be accessed by other applications.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-200",
                        "evidence": f"Clipboard usage in {item['file']}",
                    })
                    return

    def _check_cache_storage(self):
        """Check for sensitive data in cache."""
        patterns = [
            r"(?i)getCacheDir",
            r"(?i)WebView.*cache",
            r"(?i)setAppCacheEnabled\(true\)",
            r"(?i)URLCache",
        ]

        for item in self._get_strings():
            for pattern in patterns:
                if re.search(pattern, item["content"]):
                    self.findings.append({
                        "title": "Cache Storage Usage",
                        "severity": "info",
                        "confidence": "low",
                        "description": "Application uses cache storage. Cached data may persist "
                                       "and be accessible to attackers with physical access.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-524",
                        "evidence": f"Cache usage in {item['file']}",
                    })
                    return

    def _check_ios_keychain(self):
        """Check iOS Keychain usage."""
        keychain_patterns = [
            r"(?i)SecItemAdd", r"(?i)SecItemCopy",
            r"(?i)kSecClass", r"(?i)KeychainWrapper",
        ]

        found = False
        for item in self._get_strings():
            for pattern in keychain_patterns:
                if re.search(pattern, item["content"]):
                    found = True
                    break
            if found:
                break

        if not found:
            self.findings.append({
                "title": "iOS Keychain Not Used",
                "severity": "low",
                "confidence": "low",
                "description": "No Keychain usage detected. Sensitive data may be stored insecurely.",
                "category": "storage",
                "owasp": "M9",
                "cwe": "CWE-312",
                "evidence": "No Keychain API patterns found",
            })

    def _check_ios_plist_storage(self):
        """Check for sensitive data in plist files."""
        for item in self._get_strings():
            if item["file"].endswith(".plist"):
                sensitive = re.search(
                    r"(?i)(password|secret|token|api.?key|credential)", item["content"]
                )
                if sensitive:
                    self.findings.append({
                        "title": "Sensitive Data in Plist",
                        "severity": "high",
                        "description": f"Sensitive data found in {item['file']}. "
                                       "Plist files are not encrypted and easily accessible.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-312",
                        "evidence": f"Sensitive key in {item['file']}",
                    })

    def _check_ios_core_data(self):
        """Check for insecure Core Data usage."""
        for item in self._get_strings():
            if re.search(r"(?i)NSPersistentStoreCoordinator|\.xcdatamodel", item["content"]):
                if not re.search(r"(?i)NSPersistentStoreFileProtectionKey", item["content"]):
                    self.findings.append({
                        "title": "Core Data Without File Protection",
                        "severity": "medium",
                        "description": "Core Data is used without file protection. Database files "
                                       "may be accessible when device is locked.",
                        "category": "storage",
                        "owasp": "M9",
                        "cwe": "CWE-311",
                        "evidence": "Core Data without NSPersistentStoreFileProtectionKey",
                    })
