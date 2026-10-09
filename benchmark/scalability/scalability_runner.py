import os
import zipfile
import time
import tracemalloc
import csv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
RESULTS_CSV = os.path.join(RESULTS_DIR, "scalability_results.csv")

def get_size_group(size_mb):
    if size_mb < 10:
        return "Small (<10MB)"
    elif size_mb <= 50:
        return "Medium (10-50MB)"
    elif size_mb <= 150:
        return "Large (50-150MB)"
    else:
        return "Very Large (>150MB)"

def analyze_apk(apk_path):
    size_bytes = os.path.getsize(apk_path)
    size_mb = size_bytes / (1024 * 1024)
    size_group = get_size_group(size_mb)
    
    dex_count = 0
    zip_entries = 0
    
    tracemalloc.start()
    start_time = time.time()
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            namelist = apk_zip.namelist()
            zip_entries = len(namelist)
            dex_count = sum(1 for name in namelist if name.endswith('.dex') and name.startswith('classes'))
    except Exception as e:
        print(f"Error reading {os.path.basename(apk_path)}: {e}")
    
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    metadata_time = end_time - start_time
    memory_mb = peak / (1024 * 1024)
    
    return {
        "APK_Name": os.path.basename(apk_path),
        "Size_MB": round(size_mb, 2),
        "Size_Group": size_group,
        "DEX_Count": dex_count,
        "ZIP_Entries": zip_entries,
        "Metadata_Time_Seconds": round(metadata_time, 4),
        "Memory_MB": round(memory_mb, 2)
    }

def main():
    if not os.path.exists(UPLOADS_DIR):
        print(f"Uploads directory not found: {UPLOADS_DIR}")
        return
        
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    results = []
    
    for filename in os.listdir(UPLOADS_DIR):
        if filename.endswith(".apk"):
            apk_path = os.path.join(UPLOADS_DIR, filename)
            print(f"Analyzing {filename}...")
            result = analyze_apk(apk_path)
            results.append(result)
            
    if not results:
        print("No APK files found.")
        return
        
    with open(RESULTS_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "APK_Name", "Size_MB", "Size_Group", "DEX_Count", 
            "ZIP_Entries", "Metadata_Time_Seconds", "Memory_MB"
        ])
        writer.writeheader()
        writer.writerows(results)
        
    print(f"\nResults saved to {RESULTS_CSV}")
    print("\nSummary:")
    print(f"{'APK Name':<30} | {'Size (MB)':<10} | {'Time (s)':<10} | {'Memory (MB)':<10}")
    print("-" * 65)
    for r in results:
        name_short = r["APK_Name"][:27] + "..." if len(r["APK_Name"]) > 30 else r["APK_Name"]
        print(f"{name_short:<30} | {r['Size_MB']:<10} | {r['Metadata_Time_Seconds']:<10} | {r['Memory_MB']:<10}")

if __name__ == '__main__':
    main()
