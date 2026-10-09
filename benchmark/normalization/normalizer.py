"""
Finding Normalization and Taxonomy Mapper.
Converts raw scanner findings from MSA v2.0 or third-party tools (MobSF)
into normalized, canonical representation aligned with CWE, OWASP, and MASVS.
"""
from typing import Dict, Any, List, Optional
from benchmark.adapters.schema import NormalizedFinding, TestStatus


class FindingNormalizer:
    """Normalizes raw scanner findings into standardized benchmark format."""

    CWE_TO_MASVS = {
        "CWE-312": "MASVS-STORAGE",
        "CWE-922": "MASVS-STORAGE",
        "CWE-276": "MASVS-STORAGE",
        "CWE-532": "MASVS-STORAGE",
        "CWE-200": "MASVS-STORAGE",
        "CWE-326": "MASVS-CRYPTO",
        "CWE-327": "MASVS-CRYPTO",
        "CWE-321": "MASVS-CRYPTO",
        "CWE-330": "MASVS-CRYPTO",
        "CWE-287": "MASVS-AUTH",
        "CWE-280": "MASVS-AUTH",
        "CWE-862": "MASVS-AUTH",
        "CWE-319": "MASVS-NETWORK",
        "CWE-295": "MASVS-NETWORK",
        "CWE-926": "MASVS-PLATFORM",
        "CWE-927": "MASVS-PLATFORM",
        "CWE-749": "MASVS-PLATFORM",
        "CWE-942": "MASVS-PLATFORM",
        "CWE-22":  "MASVS-PLATFORM",
        "CWE-79":  "MASVS-PLATFORM",
        "CWE-89":  "MASVS-CODE",
        "CWE-78":  "MASVS-CODE",
        "CWE-470": "MASVS-CODE",
        "CWE-693": "MASVS-RESILIENCE",
        "CWE-359": "MASVS-PRIVACY"
    }

    SUPPORTED_CWES = {
        "CWE-200", "CWE-312", "CWE-922", "CWE-276", "CWE-532", "CWE-326",
        "CWE-327", "CWE-321", "CWE-330", "CWE-287", "CWE-280", "CWE-862",
        "CWE-319", "CWE-295", "CWE-926", "CWE-927", "CWE-749", "CWE-942",
        "CWE-22", "CWE-79", "CWE-89", "CWE-78", "CWE-470", "CWE-693", "CWE-798"
    }

    @classmethod
    def normalize_msa_finding(cls, raw: Dict[str, Any], target_app: str) -> NormalizedFinding:
        """Converts an internal MSA finding dictionary into a NormalizedFinding."""
        cwe_raw = str(raw.get("cwe") or raw.get("cwe_id") or "CWE-UNKNOWN").strip()
        if not cwe_raw.startswith("CWE-") and cwe_raw.isdigit():
            cwe_raw = f"CWE-{cwe_raw}"

        owasp = raw.get("owasp") or raw.get("owasp_category") or "M0"
        masvs = cls.CWE_TO_MASVS.get(cwe_raw, "MASVS-GENERAL")

        conf_raw = raw.get("confidence")
        if isinstance(conf_raw, (int, float)):
            conf_val = float(conf_raw)
        elif isinstance(conf_raw, str):
            conf_str = conf_raw.lower().strip()
            if conf_str == "high":
                conf_val = 0.9
            elif conf_str == "medium":
                conf_val = 0.7
            elif conf_str == "low":
                conf_val = 0.4
            else:
                try:
                    conf_val = float(conf_str)
                except ValueError:
                    conf_val = 0.8
        else:
            conf_val = 0.8

        return NormalizedFinding(
            finding_id=str(raw.get("id") or hash(raw.get("title", "") + str(cwe_raw))),
            target_app=target_app,
            cwe_id=cwe_raw,
            owasp_id=str(owasp),
            masvs_id=masvs,
            title=str(raw.get("title") or raw.get("name") or "Security Alert"),
            severity=str(raw.get("severity") or "MEDIUM").upper(),
            confidence=conf_val,
            detector_module=str(raw.get("module") or raw.get("source_phase") or "StaticAnalyzer"),
            evidence_location=str(raw.get("location") or raw.get("file") or "Source"),
            evidence_snippet=str(raw.get("evidence") or raw.get("snippet") or "")[:500],
            is_taint_flow=bool(raw.get("taint_flow") or "taint" in raw.get("title", "").lower()),
            source_sink_path=raw.get("path") if isinstance(raw.get("path"), list) else None,
            rag_retrieved_docs=int(raw.get("rag_docs_count") or 0),
            llm_verdict=str(raw.get("llm_verdict") or "VULNERABLE"),
            remediation_patch=raw.get("remediation") or raw.get("patch")
        )

    @classmethod
    def evaluate_test_support(cls, expected_cwe: str) -> TestStatus:
        """Determines whether a benchmark test's expected CWE is within MSA detection scope."""
        if expected_cwe in cls.SUPPORTED_CWES:
            return TestStatus.PASS
        return TestStatus.NOT_SUPPORTED
