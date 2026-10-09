"""
Real-world DroidBench local verification script.
Downloads 6 representative DroidBench APKs and runs the MSA scanner to calculate precision/recall metrics.
"""
import os
import sys
import shutil
import urllib.request
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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

# Target test APKs and their expected Ground Truth (leak = True Positive, no-leak = True Negative)
TEST_APKS = {
    "Button1.apk": {
        "url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/apk/Callbacks/Button1.apk",
        "expected_leak": True, # TP
        "description": "Leaks data on button click event (Callback leak)"
    },
    "MultiHandlers1.apk": {
        "url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/apk/Callbacks/MultiHandlers1.apk",
        "expected_leak": False, # TN
        "description": "Has multiple handlers but no active flow (Callback no-leak)"
    },
    "Obfuscation1.apk": {
        "url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/apk/AndroidSpecific/Obfuscation1.apk",
        "expected_leak": True, # TP
        "description": "Obfuscates reflection but still leaks data (Obfuscation leak)"
    },
    "UnreachableCode.apk": {
        "url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/apk/GeneralJava/UnreachableCode.apk",
        "expected_leak": False, # TN
        "description": "Contains source and sink but code path is dead (Unreachable no-leak)"
    },
    "SinkInNativeCode.apk": {
        "url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/apk/Native/SinkInNativeCode.apk",
        "expected_leak": True, # TP
        "description": "Leaks data via JNI native library sink (Native leak)"
    },
    "DynamicSource1.apk": {
        "url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/apk/DynamicLoading/DynamicSource1.apk",
        "expected_leak": True, # TP
        "description": "Dynamically loads classes and leaks data (DCL leak)"
    }
}

def download_apks(target_dir: Path):
    target_dir.mkdir(parents=True, exist_ok=True)
    print("[*] Downloading pre-compiled DroidBench APKs from official GitHub...")
    for filename, info in TEST_APKS.items():
        dest = target_dir / filename
        if not dest.exists():
            print(f"  Downloading {filename}...")
            try:
                urllib.request.urlretrieve(info["url"], str(dest))
                print(f"    [OK] Downloaded: {dest.stat().st_size} bytes")
            except Exception as e:
                print(f"    [ERROR] Failed to download {filename}: {e}")
        else:
            print(f"  {filename} already exists, skipping download.")

def run_analysis(file_path: Path, rag: RAGEngine) -> list[dict]:
    all_findings = []
    
    # Run scanner pipeline
    static = StaticAnalyzer(file_path)
    all_findings.extend(static.analyze().get("findings", []))
    
    rev = ReverseEngineer(file_path)
    all_findings.extend(rev.analyze().get("findings", []))
    
    storage = StorageAnalyzer(file_path)
    all_findings.extend(storage.analyze().get("findings", []))
    
    network = NetworkAnalyzer(file_path)
    all_findings.extend(network.analyze().get("findings", []))
    
    zeroday = ZeroDayAnalyzer(file_path)
    all_findings.extend(zeroday.analyze().get("findings", []))
    
    # Vulnerability Mapping & Deduplication
    mapper = VulnerabilityMapper()
    mapped = mapper.map_findings(all_findings)
    
    # Smart Deduplicate first
    seen = set()
    unique_mapped = []
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for f in mapped:
        key = (f.get("title", ""), f.get("category", ""), f.get("cwe", ""))
        if key not in seen:
            seen.add(key)
            unique_mapped.append(f)
        else:
            for i, existing in enumerate(unique_mapped):
                ex_key = (existing.get("title", ""), existing.get("category", ""), existing.get("cwe", ""))
                if ex_key == key:
                    if severity_rank.get(f.get("severity", "info"), 0) > severity_rank.get(existing.get("severity", "info"), 0):
                        unique_mapped[i] = f
                    break
                    
    # RAG Context Enrichment
    unique = [rag.enrich_finding(f) for f in unique_mapped]
    
    # Filter active (not suppressed as false positives)
    active = [f for f in unique if not f.get("is_false_positive", False)]
    return active

def main():
    print("=" * 60)
    print("MSA DROIDBENCH LIVE LOCAL EVALUATION RUNNER")
    print("=" * 60)
    
    # Setup test directory
    backend_dir = Path(__file__).resolve().parent.parent
    test_dir = backend_dir / "tests" / "droidbench_test"
    
    try:
        download_apks(test_dir)
        print("-" * 60)
        
        # Initialize RAGEngine
        print("[*] Initializing RAGEngine...")
        rag = RAGEngine()
        print("-" * 60)
        
        tp = 0 # True Positives
        fp = 0 # False Positives
        tn = 0 # True Negatives
        fn = 0 # False Negatives
        
        for filename, info in TEST_APKS.items():
            file_path = test_dir / filename
            if not file_path.exists():
                print(f"[!] Skipping {filename}: File download failed.")
                continue
                
            print(f"[*] Scanning DroidBench target: {filename}...")
            print(f"    Ground Truth: {'Leaks data (TP expectation)' if info['expected_leak'] else 'No leak (TN expectation)'}")
            
            # Run scan
            active_findings = run_analysis(file_path, rag)
            
            # In DroidBench, we look for data leak findings (e.g. CWE-926, CWE-22, CWE-319, or Taint Flow alerts)
            leak_alerts = [f for f in active_findings if "leak" in f.get("title", "").lower() or "taint" in f.get("title", "").lower()]
            has_leak_alert = len(leak_alerts) > 0
            
            if info["expected_leak"]:
                if has_leak_alert:
                    print("    [MATCH] Correctly detected data leak flow (TP) [OK]")
                    tp += 1
                else:
                    print("    [MISS] Missed the data leak flow (FN) [FAIL]")
                    fn += 1
            else:
                if has_leak_alert:
                    print("    [FAIL] Flagged a false leak alert (FP) [FAIL]")
                    fp += 1
                else:
                    print("    [MATCH] Correctly ignored benign flow (TN) [OK]")
                    tn += 1

                    
            print(f"    Active alerts: {len(active_findings)}")
            for f in active_findings:
                print(f"      - Title: {f.get('title')} (CWE: {f.get('cwe')})")
            print("-" * 60)
            
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        print("DROIDBENCH LIVE ACCURACY RESULTS:")
        print(f"  • True Positives (TP):  {tp}")
        print(f"  • False Positives (FP): {fp}")
        print(f"  • True Negatives (TN):  {tn}")
        print(f"  • False Negatives (FN): {fn}")
        print(f"  • Precision:            {precision:.1%}")
        print(f"  • Recall:               {recall:.1%}")
        print(f"  • F1-Score:             {f1:.3f}")
        print("=" * 60)
        
    finally:
        # Cleanup downloads to avoid taking repository space
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
