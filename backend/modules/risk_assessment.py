"""
Risk Assessment Module
Assigns CVSS scores and severity levels to vulnerabilities.
"""
from utils.logger import get_logger
from config import SEVERITY_THRESHOLDS

logger = get_logger("RiskAssessment")

SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
SEVERITY_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}


class RiskAssessor:
    def __init__(self):
        self.risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.false_positives = []
        self.verified_findings = []

    def assess(self, findings: list) -> dict:
        logger.info(f"Assessing risk for {len(findings)} findings")
        assessed = []
        self.risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.false_positives = []
        self.verified_findings = []

        for f in findings:
            is_fp = bool(f.get("is_false_positive", False))
            severity = f.get("severity", "info").lower()
            if severity not in SEVERITY_CVSS:
                severity = "info"

            if is_fp:
                # Suppressed False Positive: CVSS score is 0.0, do NOT inflate risk summary or trigger high severity alerts
                item = {**f, "cvss_score": 0.0, "severity": severity, "severity_color": "#10b981", "is_false_positive": True}
                assessed.append(item)
                self.false_positives.append(item)
            else:
                cvss_base = SEVERITY_CVSS[severity]
                # Apply confidence weighting to CVSS score
                confidence_weights = {'high': 1.0, 'medium': 0.7, 'low': 0.4}
                confidence = (f.get('confidence') or 'high').lower()
                cvss = round(cvss_base * confidence_weights.get(confidence, 1.0), 1)
                
                # Recalculate severity based on adjusted CVSS score
                if cvss >= 9.0: new_sev = "critical"
                elif cvss >= 7.0: new_sev = "high"
                elif cvss >= 4.0: new_sev = "medium"
                elif cvss >= 0.1: new_sev = "low"
                else: new_sev = "info"
                
                self.risk_summary[new_sev] += 1
                item = {**f, "cvss_score": cvss, "severity": new_sev, "severity_color": SEVERITY_COLORS.get(new_sev, "#6b7280"), "is_false_positive": False}
                assessed.append(item)
                self.verified_findings.append(item)

        actionable_vulns = [f for f in self.verified_findings if f.get("severity", "").lower() != "info"]
        info_findings = [f for f in self.verified_findings if f.get("severity", "").lower() == "info"]
        total_vulns = len(actionable_vulns)
        total_info = len(info_findings)
        total_verified = len(self.verified_findings)
        total_fp = len(self.false_positives)
        total_raw = len(findings)
        noise_reduction_pct = round((total_fp / total_raw * 100), 1) if total_raw > 0 else 0.0

        overall = "critical" if self.risk_summary["critical"] > 0 else \
                  "high" if self.risk_summary["high"] >= 1 else \
                  "medium" if self.risk_summary["medium"] >= 1 else \
                  "low" if self.risk_summary["low"] > 0 else "info"

        logger.info(f"Risk assessment complete: {total_vulns} actionable vulnerabilities, {total_info} informational notices, {total_fp} false positives suppressed ({noise_reduction_pct}% noise reduction)")

        return {
            "findings": assessed,
            "verified_findings": self.verified_findings,
            "actionable_findings": actionable_vulns,
            "false_positives": self.false_positives,
            "false_positives_count": total_fp,
            "verified_findings_count": total_verified,
            "actionable_vulnerabilities_count": total_vulns,
            "informational_count": total_info,
            "risk_summary": self.risk_summary,
            "total_findings": total_vulns,  # Actionable security vulnerabilities count
            "total_all_findings": total_verified,  # Actionable + Info
            "total_raw_findings": total_raw,
            "noise_reduction_pct": noise_reduction_pct,
            "overall_risk": overall,
            "overall_risk_color": SEVERITY_COLORS[overall],
        }
