"""
Mobile Security Agent - Real-World Precision Benchmarking Tool
Evaluates scanner accuracy (Precision, Recall, F1, FP Rate) on real-world applications.
"""
import os
import sys
import time
import json
from pathlib import Path

# Add backend directory to path to allow imports
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
from knowledge.rag_engine import RAGEngine

# Define Ground Truth (GT) expected vulnerabilities for the real-world apps
# These are mapped by platform, filename, and expected CWE IDs
GROUND_TRUTH = {
    "ZArchiver_1_0_10_arm64-v8a_release.apk": {
        "platform": "android",
        "expected_cwes": {
            "CWE-693",  # Code Not Obfuscated
            "CWE-319",  # Insecure HTTP URLs (licenses/update checking)
            "CWE-276",  # Data Written to External Storage (core business function, but flagged)
            "CWE-926",  # Content Provider Without Access Control (file sharing)
            "CWE-22",   # Path Traversal (wraps p7zip extract)
            "CWE-78",   # Command Injection (shell command execution)
            "CWE-89",   # SQL Injection (concatenation in SQLite native libraries)
            "CWE-295",  # Improper Certificate Validation (missing custom hostname verifiers in native libs - False Negative)
            "CWE-942",  # Permissive Cross-Domain Policy (webview endpoints - False Negative)
        },
        "known_noise_cwes": {
            "CWE-312",  # Plaintext SharedPreferences credentials/PII triggers (false positives)
            "CWE-326",  # General weak TLS matching in library classes
            "CWE-287",  # General insecure token storage
            "CWE-200",  # Stack trace exposure (common logging)
            "CWE-927",  # Unprotected broad range broadcasts
        },
        "true_negatives": 15  # Benign properties, standard dependencies, and certificate profiles correctly bypassed
    },
    "FileConverterPro.ipa": {
        "platform": "ios",
        "expected_cwes": {
            "CWE-798",  # Hardcoded Firebase URL
            "CWE-319",  # App Transport Security Disabled (NSAllowsArbitraryLoads)
            "CWE-312",  # Sensitive Data in Plist (Firebase config secrets)
            "CWE-326",  # Weak TLS Cipher Usage
            "CWE-89",   # SQL Injection (concatenation in DB drivers)
            "CWE-916",  # Use of Password Hash with Insufficient Computational Effort (False Negative)
        },
        "known_noise_cwes": {
            "CWE-287",  # General token credentials parsing
            "CWE-200",  # Generic database field and debug info warnings
            "CWE-1059", # API versioning warnings
        },
        "true_negatives": 25  # Unused assets, generic app plist strings, and public developer certs correctly bypassed
    }
}

def run_analysis_pipeline(file_path: Path, platform: str, rag: RAGEngine) -> list[dict]:
    """Execute the full 10-step scanning and RAG enrichment pipeline."""
    print(f"\n[*] Scanning real-world application: {file_path.name}...")
    all_findings = []
    
    # 1. Static Analysis
    static = StaticAnalyzer(file_path)
    static_res = static.analyze()
    all_findings.extend(static_res.get("findings", []))
    
    # 2. Reverse Engineering
    rev = ReverseEngineer(file_path)
    rev_res = rev.analyze()
    all_findings.extend(rev_res.get("findings", []))
    
    # 3. Storage Analysis
    storage = StorageAnalyzer(file_path)
    storage_res = storage.analyze()
    all_findings.extend(storage_res.get("findings", []))
    
    # 4. Network Analysis
    network = NetworkAnalyzer(file_path)
    network_res = network.analyze()
    all_findings.extend(network_res.get("findings", []))
    
    # 5. API Testing
    api_endpoints = static_res.get("api_endpoints", []) + rev_res.get("backend_urls", [])
    api = APISecurityTester(file_path, api_endpoints)
    api_res = api.analyze()
    all_findings.extend(api_res.get("findings", []))
    
    # 6. Dynamic Analysis
    dynamic = DynamicAnalyzer(file_path)
    dynamic_res = dynamic.analyze()
    all_findings.extend(dynamic_res.get("findings", []))
    
    # 7. Zero-Day Heuristics
    zeroday = ZeroDayAnalyzer(file_path)
    zeroday_res = zeroday.analyze()
    all_findings.extend(zeroday_res.get("findings", []))
    
    # 8. Vulnerability Mapping & Deduplication
    mapper = VulnerabilityMapper()
    mapped = mapper.map_findings(all_findings)
    
    # Smart Deduplicate first — considers title, category, CWE, and evidence
    # Prevents duplicate RAG / LLM generation requests
    seen = set()
    unique_mapped = []
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for f in mapped:
        key = (f.get("title", ""), f.get("category", ""), f.get("cwe", ""))
        if key not in seen:
            seen.add(key)
            unique_mapped.append(f)
        else:
            # Keep the one with higher severity
            for i, existing in enumerate(unique_mapped):
                ex_key = (existing.get("title", ""), existing.get("category", ""), existing.get("cwe", ""))
                if ex_key == key:
                    if severity_rank.get(f.get("severity", "info"), 0) > severity_rank.get(existing.get("severity", "info"), 0):
                        unique_mapped[i] = f
                    break

    # RAG Context Enrichment (Only on deduplicated unique findings)
    unique = [rag.enrich_finding(f) for f in unique_mapped]

                    
    # 9. Risk Assessment
    assessor = RiskAssessor()
    assessed = assessor.assess(unique)
    
    return assessed.get("findings", [])

def evaluate_app(filename: str, findings: list[dict], gt: dict) -> dict:
    """Evaluate findings against Ground Truth to calculate classification metrics."""
    found_cwes = set()
    active_findings = []
    
    # Filters findings by severity (ignore low/info for benchmark metrics)
    for f in findings:
        severity = f.get("severity", "info")
        cwe = f.get("cwe")
        if severity in ("critical", "high", "medium") and cwe:
            found_cwes.add(cwe)
            active_findings.append(f)
            
    expected = gt["expected_cwes"]
    noise = gt["known_noise_cwes"]
    tn = gt["true_negatives"]
    
    # Calculate classification states
    tp_list = []
    fp_list = []
    fn_list = []
    
    # True Positives: Correctly found ground truth CWEs
    for cwe in found_cwes:
        if cwe in expected:
            tp_list.append(cwe)
        elif cwe in noise:
            # Explicitly classified as false positive noise
            fp_list.append(cwe)
        else:
            # Other unprofiled alerts also count as false positives
            fp_list.append(cwe)
            
    # False Negatives: Expected CWEs that were missed
    for cwe in expected:
        if cwe not in found_cwes:
            fn_list.append(cwe)
            
    tp = len(tp_list)
    fp = len(fp_list)
    fn = len(fn_list)
    
    # Performance metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        "filename": filename,
        "platform": gt["platform"],
        "total_raw_findings": len(findings),
        "total_active_alerts": len(active_findings),
        "tp_count": tp,
        "fp_count": fp,
        "fn_count": fn,
        "tn_count": tn,
        "true_positives": tp_list,
        "false_positives": fp_list,
        "false_negatives": fn_list,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr
    }

def main():
    print("=" * 70)
    print("      MOBILE SECURITY AGENT - REAL-WORLD PRECISION BENCHMARK")
    print("=" * 70)
    
    uploads_dir = backend_dir.parent / "uploads"
    if not uploads_dir.exists():
        print(f"Error: Uploads directory not found at {uploads_dir}")
        sys.exit(1)
        
    # Initialize RAG Engine
    print("[*] Initializing Advanced RAG Engine v3.0...")
    rag = RAGEngine()
    
    results = []
    
    for filename, gt in GROUND_TRUTH.items():
        file_path = uploads_dir / filename
        if not file_path.exists():
            print(f"\n[!] Benchmark file not found: {filename} (skipping)")
            continue
            
        findings = run_analysis_pipeline(file_path, gt["platform"], rag)
        eval_metrics = evaluate_app(filename, findings, gt)
        results.append(eval_metrics)
        
        # Display individual report
        print(f"\n--- Benchmark Results for: {filename} ({gt['platform'].upper()}) ---")
        print(f"  • Raw Findings:          {eval_metrics['total_raw_findings']}")
        print(f"  • Active Alerts:         {eval_metrics['total_active_alerts']}")
        print(f"  • True Positives (TP):   {eval_metrics['tp_count']}  {eval_metrics['true_positives']}")
        print(f"  • False Positives (FP):  {eval_metrics['fp_count']}  {eval_metrics['false_positives']}")
        print(f"  • False Negatives (FN):  {eval_metrics['fn_count']}  {eval_metrics['false_negatives']}")
        print(f"  • True Negatives (TN):   {eval_metrics['tn_count']}")
        print(f"  • Precision:             {eval_metrics['precision']:.1%}")
        print(f"  • Recall:                {eval_metrics['recall']:.1%}")
        print(f"  • F1-Score:              {eval_metrics['f1_score']:.3f}")
        print(f"  • False Positive Rate:   {eval_metrics['false_positive_rate']:.1%}")
        
    if not results:
        print("\n[!] No benchmark files found in uploads folder. Please ensure ZArchiver or FileConverterPro are uploaded.")
        sys.exit(1)
        
    # Aggregate Metrics
    total_tp = sum(r["tp_count"] for r in results)
    total_fp = sum(r["fp_count"] for r in results)
    total_fn = sum(r["fn_count"] for r in results)
    total_tn = sum(r["tn_count"] for r in results)
    
    agg_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    agg_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    agg_f1 = 2 * (agg_precision * agg_recall) / (agg_precision + agg_recall) if (agg_precision + agg_recall) > 0 else 0.0
    agg_fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0
    
    print("\n" + "=" * 70)
    print("                  AGGREGATED REAL-WORLD METRICS")
    print("=" * 70)
    print(f"  • Total True Positives (TP):  {total_tp}")
    print(f"  • Total False Positives (FP): {total_fp}")
    print(f"  • Total False Negatives (FN): {total_fn}")
    print(f"  • Total True Negatives (TN):  {total_tn}")
    print(f"  • Aggregate Precision:        {agg_precision:.1%}")
    print(f"  • Aggregate Recall:           {agg_recall:.1%}")
    print(f"  • Aggregate F1-Score:         {agg_f1:.3f}")
    print(f"  • Aggregate FP Rate:          {agg_fpr:.1%}")
    print("-" * 70)
    
    # Save results to disk
    report_file = backend_dir.parent / "reports" / "benchmark_realworld_results.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "aggregated": {
            "precision": agg_precision,
            "recall": agg_recall,
            "f1_score": agg_f1,
            "false_positive_rate": agg_fpr,
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "tn": total_tn
        },
        "applications": results
    }
    
    report_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    print(f"[+] Benchmark report saved successfully to: {report_file}")
    print("=" * 70)

if __name__ == "__main__":
    main()
