"""
Analysis Helpers — Shared utilities for reducing false positives.
Provides line-scoped searching, confidence scoring, placeholder detection,
benign URL filtering, and cached file-string extraction.
"""
import re
import zipfile
from pathlib import Path
from functools import lru_cache
from typing import Optional

from utils.logger import get_logger

logger = get_logger("AnalysisHelpers")


# ─── BENIGN / ALLOWLIST CONSTANTS ────────────────────────────────────────────

PLACEHOLDER_VALUES = {
    "xxx", "xxxx", "xxxxx", "xxxxxxxx",
    "your_api_key", "your_api_key_here", "your_secret", "your_secret_here",
    "your_password", "your_password_here", "enter_password", "enter_your_password",
    "your_token", "your_token_here", "insert_token_here",
    "changeme", "change_me", "replace_me", "update_me",
    "todo", "fixme", "placeholder", "example", "sample", "test",
    "sk-xxxx", "sk-xxxx...", "pk_test_xxxx", "sk_test_xxxx",
    "your_db_password", "your_db_name", "your_db_username",
    "your_jwt_secret_here", "your_aws_access_key", "your_aws_secret_key",
    "your_s3_bucket", "none", "null", "undefined", "n/a", "na",
    "password", "secret", "token", "key",  # bare keyword-only values
}

BENIGN_URL_PATTERNS = {
    "schemas.android.com",
    "schemas.microsoft.com",
    "xmlpull.org",
    "apache.org",
    "w3.org",
    "www.w3.org",
    "xml.org",
    "java.sun.com",
    "xmlns.jcp.org",
    "purl.org",
    "example.com",
    "example.org",
    "example.net",
    "placeholder.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "10.0.2.2",       # Android emulator host
    "10.0.3.2",       # Genymotion emulator host
}

BENIGN_URL_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://xmlpull.org",
    "http://xml.org",
    "http://java.sun.com",
    "http://xmlns.jcp.org",
    "http://purl.org",
    "http://ns.adobe.com",
    "http://apache.org",
    "http://www.apache.org",
    "http://example.com",
    "http://example.org",
    "https://example.com",
    "https://example.org",
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "http://0.0.0.0",
    "http://10.0.2.2",
    "http://10.0.3.2",
)

COMMENT_PATTERNS = re.compile(r'(//.*$|/\*.*?\*/|#.*$)', re.MULTILINE)

SECURITY_CONTEXT_KEYWORDS = {
    "encrypt", "decrypt", "password", "passwd", "credential",
    "token", "secret", "key", "hash", "salt", "nonce", "iv",
    "cipher", "crypto", "sign", "auth", "session", "private",
}


# ─── LINE-SCOPED SEARCH ─────────────────────────────────────────────────────

class LineMatch:
    """Represents a single regex match with line context."""
    __slots__ = ("line_number", "line_content", "match_text", "file_name", "context_before", "context_after")

    def __init__(self, line_number, line_content, match_text, file_name="",
                 context_before=None, context_after=None):
        self.line_number = line_number
        self.line_content = line_content.strip()
        self.match_text = match_text
        self.file_name = file_name
        self.context_before = context_before or []
        self.context_after = context_after or []

    def nearby_text(self):
        """Returns all context lines as a single string for proximity checks."""
        return "\n".join(self.context_before + [self.line_content] + self.context_after)


def line_scoped_search(content: str, pattern: str, file_name: str = "",
                       context_lines: int = 2, max_matches: int = 50,
                       case_insensitive: bool = True) -> list[LineMatch]:
    """
    Searches content line-by-line for a regex pattern.
    Returns LineMatch objects with surrounding context.
    This prevents cross-line `.*` false matches that occur when running
    regex against entire file contents.
    """
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        return []

    lines = content.split("\n")
    matches = []

    for i, line in enumerate(lines):
        m = compiled.search(line)
        if m:
            ctx_before = [lines[j].strip() for j in range(max(0, i - context_lines), i)]
            ctx_after = [lines[j].strip() for j in range(i + 1, min(len(lines), i + 1 + context_lines))]
            matches.append(LineMatch(
                line_number=i + 1,
                line_content=line,
                match_text=m.group(0),
                file_name=file_name,
                context_before=ctx_before,
                context_after=ctx_after,
            ))
            if len(matches) >= max_matches:
                break

    return matches


def proximity_search(content: str, pattern_a: str, pattern_b: str,
                     max_line_distance: int = 5, file_name: str = "") -> list[LineMatch]:
    """
    Finds occurrences where pattern_a and pattern_b appear within
    max_line_distance lines of each other. Returns matches for pattern_a
    only when pattern_b is nearby. Prevents false matches where two
    unrelated patterns appear far apart in the same file.
    """
    lines = content.split("\n")
    compiled_a = re.compile(pattern_a, re.IGNORECASE)
    compiled_b = re.compile(pattern_b, re.IGNORECASE)

    a_lines = [i for i, line in enumerate(lines) if compiled_a.search(line)]
    b_lines = set(i for i, line in enumerate(lines) if compiled_b.search(line))

    matches = []
    for a_idx in a_lines:
        for offset in range(-max_line_distance, max_line_distance + 1):
            if (a_idx + offset) in b_lines:
                m = compiled_a.search(lines[a_idx])
                if m:
                    matches.append(LineMatch(
                        line_number=a_idx + 1,
                        line_content=lines[a_idx],
                        match_text=m.group(0),
                        file_name=file_name,
                    ))
                break

    return matches


# ─── CONFIDENCE SCORING ──────────────────────────────────────────────────────

def is_placeholder_value(value: str) -> bool:
    """
    Returns True if the value looks like a placeholder, template, or dummy value
    that should not be flagged as a real hardcoded secret.
    """
    if not value or not isinstance(value, str):
        return True

    cleaned = value.strip().strip("'\"").lower()

    # Exact match against known placeholders
    if cleaned in PLACEHOLDER_VALUES:
        return True

    # Starts with common placeholder prefixes
    placeholder_prefixes = ("your_", "enter_", "insert_", "replace_", "update_",
                            "todo", "fixme", "example_", "sample_", "test_",
                            "dummy_", "fake_", "mock_")
    if any(cleaned.startswith(p) for p in placeholder_prefixes):
        return True

    # Check if common placeholder terms are contained as substrings anywhere
    placeholder_terms = ("placeholder", "your_key", "your_secret", "dummy", "fake", 
                         "example", "change_me", "changeme", "_here", "todo", "fixme")
    if any(term in cleaned for term in placeholder_terms):
        return True

    # All same character (e.g., "xxxxxxxx", "********")
    if len(set(cleaned)) <= 2 and len(cleaned) >= 3:
        return True

    # Contains ellipsis or trailing dots (e.g., "sk-xxxx...")
    if "..." in cleaned or cleaned.endswith(".."):
        return True

    # Too short to be a real secret (less than 6 chars)
    if len(cleaned) < 6:
        return True

    return False


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string, representing its randomness."""
    if not text:
        return 0.0
    import math
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_secret(value: str, min_entropy: float = 3.2, min_length: int = 8) -> bool:
    """
    Returns True if the string is likely a cryptographic key, token, or secret
    based on length, placeholder exclusion, and Shannon entropy.
    """
    if not value or len(value) < min_length:
        return False
    
    # Exclude common placeholder words
    if is_placeholder_value(value):
        return False
        
    # Calculate Shannon entropy
    entropy = calculate_shannon_entropy(value)
    
    # High-entropy check (e.g., base64 or hex keys generally score > 3.2)
    return entropy >= min_entropy


def is_third_party_library(file_path: str) -> bool:
    """
    Returns True if the file path belongs to a common third-party package
    or system framework, indicating the developer has no direct control over it.
    """
    if not file_path:
        return False
        
    lower_path = file_path.lower().replace("\\", "/")
    
    # Common library path indicators
    library_indicators = (
        # Android libraries
        "androidx/", "android/support/", "kotlin/", "com/google/android/",
        "com/google/gson/", "com/google/firebase/", "com/fasterxml/jackson/",
        "okhttp3/", "okio/", "rx/java/", "io/reactivex/", "com/squareup/",
        "com/bumptech/glide/", "com/facebook/share/", "com/unity3d/",
        "org/apache/commons/", "org/intellij/", "org/jetbrains/",
        # iOS libraries
        "pods/", "frameworks/flutter.framework/", "frameworks/unityframework/",
        "frameworks/firebase", "frameworks/googlesignin", "frameworks/facebook",
        "payload/runner.app/frameworks/" # third-party embedded frameworks
    )
    
    # Check if any library indicators are present in the path
    # Make sure we don't match the main app code (which is typically in the runner or custom package)
    if any(lib in lower_path for lib in library_indicators):
        # Exclude main iOS App Runner source files if they somehow contain these keywords
        if "payload/runner.app/" in lower_path and not "/frameworks/" in lower_path:
            return False
        return True
        
    return False


def is_in_comment(line: str) -> bool:
    """Check if the line appears to be a code comment."""
    stripped = line.strip()
    return (stripped.startswith("//") or
            stripped.startswith("#") or
            stripped.startswith("/*") or
            stripped.startswith("*") or
            stripped.startswith("<!--"))


def compute_confidence(match: LineMatch, category: str = "") -> str:
    """
    Computes a confidence level (high/medium/low) for a finding
    based on contextual signals.
    """
    line = match.line_content

    # Matches in comments are low confidence
    if is_in_comment(line):
        return "low"

    # Matches in third-party libraries are low confidence
    if is_third_party_library(match.file_name):
        return "low"

    # Matches in test/example/mock files are low confidence
    lower_name = match.file_name.lower()
    if any(kw in lower_name for kw in ("test", "example", "sample", "mock", "demo", "fixture")):
        return "low"

    # For secret detection: check if the value looks like a placeholder
    if category == "secrets":
        # Try to extract the value portion after = or :
        value_match = re.search(r'[=:]\s*["\']?([^"\'\s]+)', line)
        if value_match and is_placeholder_value(value_match.group(1)):
            return "low"

    # Matches in resource/layout/string XML files are lower confidence
    if any(ext in lower_name for ext in ("strings.xml", "layout", "values", ".properties")):
        return "medium"

    return "high"


# ─── URL FILTERING ───────────────────────────────────────────────────────────

def is_benign_url(url: str) -> bool:
    """Returns True if the URL is a known-benign pattern that should not be flagged."""
    url_lower = url.lower().strip()

    # Check against prefix list
    if any(url_lower.startswith(prefix) for prefix in BENIGN_URL_PREFIXES):
        return True

    # Check if the hostname portion matches any benign domain
    try:
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed = urlparse(url_lower)
        hostname = parsed.hostname or ""
        if hostname in BENIGN_URL_PATTERNS:
            return True
        # Check if it's a private IP range
        if hostname.startswith(("10.", "192.168.", "172.")):
            return True
    except Exception:
        pass

    return False


# ─── CACHED FILE STRING EXTRACTION ──────────────────────────────────────────

_string_cache: dict[str, list[dict]] = {}


def get_file_strings(zip_path: str | Path, force_refresh: bool = False) -> list[dict]:
    """
    Extracts readable strings from a ZIP (APK/IPA) file.
    Results are cached so multiple modules don't re-read the ZIP.
    Each entry has {'file': filename, 'content': decoded_text}.
    """
    cache_key = str(zip_path)
    if not force_refresh and cache_key in _string_cache:
        return _string_cache[cache_key]

    results = []
    text_extensions = (".xml", ".json", ".properties", ".yml", ".yaml", ".txt",
                       ".cfg", ".conf", ".ini", ".html", ".js", ".plist")

    try:
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            for name in zf.namelist():
                if name.endswith(text_extensions):
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        if content.strip():
                            results.append({"file": name, "content": content})
                    except Exception:
                        continue

            # Also extract strings from binary files (DEX, SO)
            for name in zf.namelist():
                if name.endswith((".dex", ".so")):
                    try:
                        raw = zf.read(name)
                        # Extract printable ASCII strings of length >= 8
                        strings = re.findall(rb'[\x20-\x7e]{8,}', raw)
                        if strings:
                            decoded = "\n".join(s.decode("ascii", errors="ignore") for s in strings)
                            results.append({"file": name, "content": decoded})
                    except Exception:
                        continue

    except (zipfile.BadZipFile, FileNotFoundError) as e:
        logger.error(f"Failed to read ZIP file {zip_path}: {e}")

    _string_cache[cache_key] = results
    return results


def clear_string_cache():
    """Clears the file string cache. Call after a scan completes."""
    _string_cache.clear()
