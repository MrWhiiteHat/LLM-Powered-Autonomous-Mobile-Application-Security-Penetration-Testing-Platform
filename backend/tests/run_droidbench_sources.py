"""
Real-world DroidBench local verification script.
Downloads 10 representative DroidBench Java files directly, packages them as mock APK archives,
and runs the MSA scanner to calculate precision/recall metrics.
"""
import os
import sys
import zipfile
import shutil
import urllib.request
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.static_analysis import StaticAnalyzer
from modules.reverse_engineering import ReverseEngineer
from modules.storage_analysis import StorageAnalyzer
from modules.network_analysis import NetworkAnalyzer
from modules.zero_day_analyzer import ZeroDayAnalyzer
from modules.vulnerability_mapper import VulnerabilityMapper
from knowledge.rag_engine import RAGEngine

# Target test cases and their expected ground truth (leak = True Positive, no-leak = True Negative)
TEST_CASES = {
    "DirectLeak1": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/AndroidSpecific/DirectLeak1/app/src/main/java/de/ecspride/MainActivity.java",
        "expected_leak": True,
        "description": "Direct leak of device ID to log (Callback/Direct leak)"
    },
    "LogNoLeak": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/AndroidSpecific/LogNoLeak/app/src/main/java/de/ecspride/LogNoLeak.java",
        "expected_leak": False,
        "description": "Logs constant string, no actual device ID flow (Direct no-leak)"
    },
    "Obfuscation1": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/AndroidSpecific/Obfuscation1/app/src/main/java/de/ecspride/MainActivity.java",
        "expected_leak": True,
        "description": "Obfuscates reflection but still leaks IMEI to log (Obfuscation leak)"
    },
    "InactiveActivity": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/AndroidSpecific/InactiveActivity/app/src/main/java/de/ecspride/InactiveActivity.java",
        "expected_leak": False,
        "description": "Vulnerable code path exists but inside an uninstantiated activity (Inactive no-leak)"
    },
    "Button1": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/Callbacks/Button1/app/src/main/java/de/ecspride/Button1.java",
        "expected_leak": True,
        "description": "Leaks data on button click event (Callback leak)"
    },
    "MultiHandlers1": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/Callbacks/MultiHandlers1/app/src/main/java/de/ecspride/MultiHandlers1.java",
        "expected_leak": False,
        "description": "Has multiple handlers but no active leakage path (Callback no-leak)"
    },
    "UnreachableCode": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/GeneralJava/UnreachableCode/app/src/main/java/de/ecspride/UnreachableCode.java",
        "expected_leak": False,
        "description": "Contains source and sink but inside dead code (Unreachable no-leak)"
    },
    "ActivityLifecycle1": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/Lifecycle/ActivityLifecycle1/app/src/main/java/de/ecspride/ActivityLifecycle1.java",
        "expected_leak": True,
        "description": "Leaks data during activity lifecycle events (Lifecycle leak)"
    },
    "ActivityLifecycle2": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/Lifecycle/ActivityLifecycle2/app/src/main/java/de/ecspride/MainActivity.java",
        "expected_leak": True,
        "description": "Leaks data in secondary lifecycle handlers (Lifecycle leak)"
    },
    "ImplicitFlow1": {
        "raw_url": "https://raw.githubusercontent.com/secure-software-engineering/DroidBench/master/projects/ImplicitFlows/ImplicitFlow1/app/src/main/java/de/ecspride/ImplicitFlow1.java",
        "expected_leak": True,
        "description": "Leaks data through branch conditions (Implicit flow leak)"
    }
}

def download_and_package_case(case_name: str, info: dict, target_dir: Path) -> Path:
    # 1. Download Java file content
    req = urllib.request.Request(info["raw_url"], headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        java_content = response.read().decode("utf-8", errors="ignore")
    
    # 2. Package it into a mock zip with APK extension
    mock_apk_path = target_dir / f"{case_name}.apk"
    with zipfile.ZipFile(mock_apk_path, "w") as zf:
        zf.writestr("MainActivity.java", java_content)
        # Put mock AndroidManifest.xml inside so manifest parsing does not fail
        manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="de.ecspride.{case_name.lower()}">
    <application android:allowBackup="true" android:debuggable="true">
        <activity android:name="de.ecspride.MainActivity" android:exported="true" />
    </application>
</manifest>
"""
        zf.writestr("AndroidManifest.xml", manifest)
        
    return mock_apk_path

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
    print("MSA DROIDBENCH LIVE SOURCE-CODE BENCHMARK RUNNER")
    print("=" * 60)
    
    # Setup test directory
    backend_dir = Path(__file__).resolve().parent.parent
    test_dir = backend_dir / "tests" / "droidbench_source_test"
    test_dir.mkdir(parents=True, exist_ok=True)
        
    try:
        # Initialize RAGEngine
        print("[*] Initializing RAGEngine...")
        rag = RAGEngine()
        print("-" * 60)
        
        tp = 0 # True Positives
        fp = 0 # False Positives
        tn = 0 # True Negatives
        fn = 0 # False Negatives
        
        for case_name, info in TEST_CASES.items():
            print(f"[*] Downloading, packaging, and scanning DroidBench target: {case_name}...")
            print(f"    Description: {info['description']}")
            print(f"    Expected: {'Leak (TP)' if info['expected_leak'] else 'No Leak (TN)'}")
            
            # Package case
            try:
                mock_apk = download_and_package_case(case_name, info, test_dir)
            except Exception as e:
                print(f"    [ERROR] Failed to download/package case {case_name}: {e}")
                continue
            
            # Scan mock APK containing source file
            active_findings = run_analysis(mock_apk, rag)
            
            # Check if sensitive leakage is flagged (CWE-532 log leaks or Zero-day leaks)
            leak_alerts = [f for f in active_findings if f.get("cwe") in ("CWE-532", "CWE-926", "CWE-319", "CWE-22")]
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
                print(f"      - Title: {f.get('title')} (CWE: {f.get('cwe')}) (Severity: {f.get('severity')})")
            print("-" * 60)
                
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        print("DROIDBENCH LIVE SOURCE-CODE BENCHMARK RESULTS:")
        print(f"  • True Positives (TP):  {tp}")
        print(f"  • False Positives (FP): {fp}")
        print(f"  • True Negatives (TN):  {tn}")
        print(f"  • False Negatives (FN): {fn}")
        print(f"  • Precision:            {precision:.1%}")
        print(f"  • Recall:               {recall:.1%}")
        print(f"  • F1-Score:             {f1:.3f}")
        print("=" * 60)
        
    finally:
        # Cleanup temporary files
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
