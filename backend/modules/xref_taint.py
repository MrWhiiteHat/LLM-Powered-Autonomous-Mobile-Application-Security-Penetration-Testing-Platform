"""
XREF Taint Analyzer
-------------------
Parser-independent taint detection built directly on androguard's cross-reference
(XREF) graph, so it works on any APK without needing decompiled source to parse
cleanly. It captures the class of privacy/injection leaks that DroidBench measures
and that the source-text regex detectors miss.

Heuristic (recall-oriented over-approximation):
  * A "source" is an API returning sensitive or untrusted data (device identifiers,
    location, accounts, Intent extras, user input).
  * A "sink" is an API that exfiltrates or dangerously consumes data (SMS, network,
    logs, command exec, SQL, WebView, file write).
  * A method is flagged when it obtains a source AND reaches a sink — directly, or
    transitively through the app's own call graph (one-level inter-procedural
    reachability). The sink category selects the reported CWE.

Findings are emitted at medium confidence (heuristic, no full dataflow), which keeps
them out of the noise-drop filter while signalling that they warrant review.
"""
from pathlib import Path

from utils.logger import get_logger

logger = get_logger("XrefTaint")

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except Exception:
    ANDROGUARD_AVAILABLE = False


# ─── SOURCES ────────────────────────────────────────────────────────────────
# Sensitive-identifier / PII / location sources (privacy leaks)
PII_SOURCES = {
    "getDeviceId", "getImei", "getMeid", "getSubscriberId", "getSimSerialNumber",
    "getLine1Number", "getSerial", "getMacAddress", "getAccounts", "getAccountsByType",
    "getLastKnownLocation", "getLatitude", "getLongitude", "getCellLocation",
    "getAndroidId",
}
# Untrusted-input sources (injection leaks)
INPUT_SOURCES = {
    "getIntent", "getExtras", "getStringExtra", "getData", "getQueryParameter",
    "getText", "getInputStream", "getParameter", "readLine", "getHeader",
    "getSerializableExtra", "getParcelableExtra",
}
ALL_SOURCES = PII_SOURCES | INPUT_SOURCES


# ─── SINKS (name -> (cwe, owasp, label)) ────────────────────────────────────
SINKS = {
    # Exfiltration channels
    "sendTextMessage":        ("CWE-200", "M6", "SMS"),
    "sendMultipartTextMessage": ("CWE-200", "M6", "SMS"),
    "sendDataMessage":        ("CWE-200", "M6", "SMS"),
    "openConnection":         ("CWE-319", "M5", "network"),
    "getOutputStream":        ("CWE-319", "M5", "network"),
    "newCall":                ("CWE-319", "M5", "network (OkHttp)"),
    "execute":                ("CWE-319", "M5", "network"),
    # Logging
    "d": ("CWE-532", "M8", "log"), "v": ("CWE-532", "M8", "log"),
    "i": ("CWE-532", "M8", "log"), "w": ("CWE-532", "M8", "log"),
    "e": ("CWE-532", "M8", "log"), "println": ("CWE-532", "M8", "log"),
    # Command / dynamic execution
    "exec": ("CWE-78", "M4", "command exec"),
    # SQL
    "rawQuery": ("CWE-89", "M4", "SQL"), "execSQL": ("CWE-89", "M4", "SQL"),
    # WebView
    "loadUrl": ("CWE-749", "M4", "WebView"),
    "evaluateJavascript": ("CWE-749", "M4", "WebView"),
    "addJavascriptInterface": ("CWE-749", "M4", "WebView"),
    # File write (path/content injection)
    "openFileOutput": ("CWE-22", "M4", "file write"),
}
# Log sinks share single-letter names (Log.d/e/i...) that collide with unrelated
# one-letter methods; only treat them as sinks when the owning class is a Logger.
_LOG_CLASSES = ("Landroid/util/Log", "Ljava/io/PrintStream", "Ljava/util/logging/")
_LOG_NAMES = {"d", "v", "i", "w", "e", "println"}

_SKIP_CONTAINER_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Ldalvik/", "Lcom/google/android/gms/", "Lcom/google/firebase/",
)


def _dotted(class_name: str) -> str:
    n = class_name
    if n.startswith("L"):
        n = n[1:]
    if n.endswith(";"):
        n = n[:-1]
    return n.replace("/", ".")


class XrefTaintAnalyzer:
    def __init__(self, file_path: Path, platform: str = "android"):
        self.file_path = Path(file_path)
        self.platform = platform
        self.findings = []
        self.stats = {"methods_scanned": 0, "taint_flows": 0}

    def analyze(self) -> dict:
        if self.platform != "android" or not ANDROGUARD_AVAILABLE:
            return {"findings": [], "xref_stats": self.stats}
        try:
            _, _, dx = AnalyzeAPK(str(self.file_path))
        except Exception as e:
            logger.warning(f"XREF taint: androguard could not analyze APK: {e}")
            return {"findings": [], "xref_stats": self.stats}

        # Pass 1: for every app method, record which sources and sinks it calls
        # directly, and which app methods it calls (for the call graph).
        per_method = {}   # key -> {"sources": set, "sinks": set, "calls": set, "class": str, "name": str}
        for mca in dx.get_methods():
            if mca.is_external():
                continue
            m = mca.get_method()
            try:
                cls = m.get_class_name()
                if any(cls.startswith(p) for p in _SKIP_CONTAINER_PREFIXES):
                    continue
                key = (cls, m.get_name(), str(m.get_descriptor()))
            except Exception:
                continue

            sources, sinks, calls = set(), set(), set()
            for item in mca.get_xref_to():
                try:
                    called = item[1]
                    cname = called.get_name()
                    cclass = called.get_class_name()
                except Exception:
                    continue
                if cname in ALL_SOURCES:
                    sources.add(cname)
                if cname in SINKS:
                    # disambiguate single-letter log sinks by owning class
                    if cname in _LOG_NAMES and not any(cclass.startswith(c) for c in _LOG_CLASSES):
                        pass
                    else:
                        sinks.add(cname)
                # app-internal call edge for inter-procedural reach
                if not any(cclass.startswith(p) for p in _SKIP_CONTAINER_PREFIXES):
                    calls.add((cclass, cname, str(called.get_descriptor()) if hasattr(called, "get_descriptor") else ""))

            self.stats["methods_scanned"] += 1
            per_method[key] = {"sources": sources, "sinks": sinks, "calls": calls,
                               "class": cls, "name": m.get_name()}

        # Pass 2: transitive "reaches a sink" set over the app call graph.
        reaches = {k: dict(v["sinks"] and {next(iter(v["sinks"])): None} or {}) for k, v in per_method.items()}
        # Represent reach as: key -> set of sink names reachable
        reach_sinks = {k: set(v["sinks"]) for k, v in per_method.items()}
        changed = True
        guard = 0
        while changed and guard < 10:
            changed = False
            guard += 1
            for k, v in per_method.items():
                before = len(reach_sinks[k])
                for callee in v["calls"]:
                    if callee in reach_sinks:
                        reach_sinks[k] |= reach_sinks[callee]
                if len(reach_sinks[k]) != before:
                    changed = True

        # Pass 3: a method with a source that reaches any sink -> taint flow.
        seen = set()
        for k, v in per_method.items():
            if not v["sources"]:
                continue
            sinks_reached = reach_sinks[k]
            if not sinks_reached:
                continue
            # Report one finding per (method, sink-category)
            for sink_name in sorted(sinks_reached):
                cwe, owasp, label = SINKS[sink_name]
                dedup = (v["class"], v["name"], cwe)
                if dedup in seen:
                    continue
                seen.add(dedup)

                src_kind = "sensitive identifier/PII" if v["sources"] & PII_SOURCES else "untrusted input"
                src_list = ", ".join(sorted(v["sources"]))
                self.stats["taint_flows"] += 1
                self.findings.append({
                    "title": f"Taint Flow: {src_kind} reaches {label} sink",
                    "severity": "high",
                    "description": (
                        f"Data from {src_kind} source(s) [{src_list}] reaches a "
                        f"{label} sink ({sink_name}) in {_dotted(v['class'])}.{v['name']}(). "
                        f"This can leak sensitive data or allow injection."
                    ),
                    "category": "xref-taint",
                    "owasp": owasp,
                    "cwe": cwe,
                    "file": _dotted(v["class"]),
                    "evidence": f"{src_list} -> {sink_name} in {_dotted(v['class'])}.{v['name']}()",
                    "confidence": "medium",
                })

        logger.info(f"XREF taint analysis complete — {self.stats['methods_scanned']} methods, "
                    f"{self.stats['taint_flows']} taint flows")
        return {"findings": self.findings, "xref_stats": self.stats}
