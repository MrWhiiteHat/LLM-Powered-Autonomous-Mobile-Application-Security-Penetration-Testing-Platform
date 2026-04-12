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

    def assess(self, findings: list) -> dict:
        logger.info(f"Assessing risk for {len(findings)} findings")
        assessed = []
        for f in findings:
            severity = f.get("severity", "info").lower()
            if severity not in SEVERITY_CVSS:
                severity = "info"
            self.risk_summary[severity] += 1
            cvss = SEVERITY_CVSS[severity]
            assessed.append({**f, "cvss_score": cvss, "severity": severity, "severity_color": SEVERITY_COLORS[severity]})

        total = sum(self.risk_summary.values())
        overall = "critical" if self.risk_summary["critical"] > 0 else \
                  "high" if self.risk_summary["high"] > 2 else \
                  "medium" if self.risk_summary["medium"] > 3 else \
                  "low" if self.risk_summary["low"] > 0 else "info"

        return {
            "findings": assessed,
            "risk_summary": self.risk_summary,
            "total_findings": total,
            "overall_risk": overall,
            "overall_risk_color": SEVERITY_COLORS[overall],
        }
