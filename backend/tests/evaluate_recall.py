"""
Recall / Precision Benchmark Harness
------------------------------------
Runs the full analysis pipeline against a curated, labeled APK set
(backend/tests/labels.json) and reports recall (did we recover the known
vulnerabilities?), precision on benign apps, and per-target missed CWEs.

This is the objective gate for the recall-upgrade work: a change that lowers
recall on the labeled set must not ship.

Usage:
    python backend/tests/evaluate_recall.py
    MSA_DISABLE_ANDROGUARD=1 python backend/tests/evaluate_recall.py   # baseline
"""
import os
import sys
import json
import shutil
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from modules.static_analysis import StaticAnalyzer
from modules.reverse_engineering import ReverseEngineer
from modules.storage_analysis import StorageAnalyzer
from modules.network_analysis import NetworkAnalyzer
from modules.api_testing import APISecurityTester
from modules.dynamic_analysis import DynamicAnalyzer
from modules.zero_day_analyzer import ZeroDayAnalyzer
from modules.vulnerability_mapper import VulnerabilityMapper
from modules.risk_assessment import RiskAssessor
from utils.decompile import decompile_apk

# Reuse the synthetic dataset generator from the precision benchmark.
from evaluate_precision import generate_mock_datasets

REPO_ROOT = backend_dir.parent
LABELS_FILE = Path(__file__).resolve().parent / "labels.json"
ALERT_SEVERITIES = ("critical", "high", "medium")


def run_pipeline(file_path: Path, platform: str) -> list[dict]:
    """Run the analysis pipeline (mirrors main.run_full_analysis) and return findings."""
    all_findings = []

    decompiled_dir, engine = decompile_apk(file_path, platform)

    static = StaticAnalyzer(file_path, decompiled_dir=decompiled_dir)
    static_results = static.analyze()
    all_findings.extend(static_results.get("findings", []))

    # AST taint stage (runs whenever any decompiler produced sources)
    if decompiled_dir:
        try:
            from modules.ast_analyzer import ASTAnalyzer
            ast = ASTAnalyzer(decompiled_dir)
            all_findings.extend(ast.analyze().get("findings", []))
        except Exception:
            pass
        # XREF taint stage (parser-independent; androguard-based)
        try:
            from modules.xref_taint import XrefTaintAnalyzer
            xt = XrefTaintAnalyzer(file_path, platform)
            all_findings.extend(xt.analyze().get("findings", []))
        except Exception:
            pass

    rev = ReverseEngineer(file_path)
    rev_results = rev.analyze()
    all_findings.extend(rev_results.get("findings", []))

    storage = StorageAnalyzer(file_path)
    all_findings.extend(storage.analyze().get("findings", []))

    network = NetworkAnalyzer(file_path)
    all_findings.extend(network.analyze().get("findings", []))

    api_endpoints = static_results.get("api_endpoints", []) + rev_results.get("backend_urls", [])
    api = APISecurityTester(file_path, api_endpoints)
    all_findings.extend(api.analyze().get("findings", []))

    dynamic = DynamicAnalyzer(file_path)
    all_findings.extend(dynamic.analyze().get("findings", []))

    zeroday = ZeroDayAnalyzer(file_path)
    all_findings.extend(zeroday.analyze().get("findings", []))

    mapper = VulnerabilityMapper()
    mapped = mapper.map_findings(all_findings)

    assessor = RiskAssessor()
    assessed = assessor.assess(mapped)
    return assessed.get("findings", []), engine


def active_findings(findings: list[dict]) -> list[dict]:
    """Findings that would surface as alerts (not suppressed, actionable severity)."""
    out = []
    for f in findings:
        if f.get("suppressed"):
            continue
        if f.get("severity") in ALERT_SEVERITIES:
            out.append(f)
    return out


def resolve_targets(labels: dict, temp_dir: Path) -> list[dict]:
    """Materialize target APK paths (generate synthetic ones, resolve file refs)."""
    clean_apk = vuln_apk = None
    resolved = []
    for t in labels.get("targets", []):
        src = t.get("source")
        if src == "generated":
            if clean_apk is None:
                clean_apk, vuln_apk = generate_mock_datasets(temp_dir)
            path = vuln_apk if t["id"] == "mock_vulnerable" else clean_apk
        else:
            path = REPO_ROOT / src
            if not path.exists():
                print(f"  [skip] {t['id']}: file not found ({path})")
                continue
        resolved.append({**t, "path": path})
    return resolved


def main():
    print("=" * 64)
    print("MSA RECALL / PRECISION BENCHMARK")
    engine_note = "androguard DISABLED (baseline)" if os.getenv("MSA_DISABLE_ANDROGUARD") else "full engine"
    print(f"Mode: {engine_note}")
    print("=" * 64)

    labels = json.loads(LABELS_FILE.read_text(encoding="utf-8"))
    temp_dir = REPO_ROOT / "uploads" / "recall_bench"
    temp_dir.mkdir(parents=True, exist_ok=True)

    total_expected = total_recovered = 0
    total_fp = 0

    try:
        for t in resolve_targets(labels, temp_dir):
            findings, engine = run_pipeline(t["path"], t["platform"])
            alerts = active_findings(findings)
            found_cwes = {f.get("cwe") for f in alerts if f.get("cwe")}
            expected = set(t.get("expected_cwes", []))

            print(f"\n>> {t['id']}  (decompiler: {engine})")
            if expected:
                recovered = expected & found_cwes
                missed = expected - found_cwes
                total_expected += len(expected)
                total_recovered += len(recovered)
                rec = len(recovered) / len(expected) if expected else 1.0
                print(f"    recall: {len(recovered)}/{len(expected)} = {rec:.0%}")
                if missed:
                    print(f"    MISSED: {', '.join(sorted(missed))}")
            else:
                # benign target: alerts are false positives
                cap = t.get("max_alerts", 0)
                fp = max(0, len(alerts) - cap)
                total_fp += fp
                print(f"    alerts: {len(alerts)} (cap {cap}) -> false positives: {fp}")
                for f in alerts:
                    print(f"      [FP] {f.get('title')} | {f.get('severity')} | {f.get('cwe')}")

        print("\n" + "=" * 64)
        overall_recall = (total_recovered / total_expected) if total_expected else 1.0
        print(f"OVERALL RECALL:    {total_recovered}/{total_expected} = {overall_recall:.1%}")
        print(f"FALSE POSITIVES:   {total_fp} (goal: 0)")
        print("=" * 64)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
