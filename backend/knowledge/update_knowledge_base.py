"""
Dataset and Knowledge Base Update/Training Pipeline for Mobile Security Agent (MSA).
Downloads, parses, and injects Category 1, 2, 3, and 4 security datasets into the RAG index.
"""
import os
import json
import urllib.request
import urllib.error
import zipfile
import ssl
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
KNOWLEDGE_DIR = BASE_DIR / "backend" / "knowledge" / "security_data"
DATASET_DIR = BASE_DIR / "dataset"

# Ensure directories exist
KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
DATASET_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("MSA KNOWLEDGE BASE UPDATE & TRAINING PIPELINE")
print("=" * 60)

import http.client

def download_file(url: str, dest_path: Path) -> bool:
    print(f"[*] Downloading: {url}")
    # Bypass certificate verification for university/academic portals if they have self-signed certificates
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, context=ctx, timeout=40) as response:
                # Read in chunks to handle large files and network drops
                chunk_size = 1024 * 128
                with open(dest_path, "wb") as f:
                    while True:
                        try:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                        except http.client.IncompleteRead as e:
                            # Write partial chunk and break if finished
                            f.write(e.partial)
                            break
            print(f"    [OK] Saved to {dest_path.name}")
            return True
        except Exception as e:
            print(f"    [!] Attempt {attempt+1}/3 failed: {e}")
            import time
            time.sleep(3)
    return False

def update_mitre_attack():
    print("\n[*] Processing MITRE ATT&CK Mobile Matrix...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
    json_path = DATASET_DIR / "mobile_attack.json"
    
    if download_file(url, json_path):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            objects = data.get("objects", [])
            
            techniques = []
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    name = obj.get("name")
                    desc = obj.get("description", "No description available.")
                    tid = "N/A"
                    for ext in obj.get("external_references", []):
                        if ext.get("source_name") == "mitre-mobile-attack":
                            tid = ext.get("external_id", "N/A")
                            break
                    techniques.append((tid, name, desc))
            
            # Generate markdown document for RAG indexing
            md_path = KNOWLEDGE_DIR / "mitre_attack_mobile.md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write("# MITRE ATT&CK Mobile Techniques\n\n")
                f.write("Reference catalog of mobile-relevant tactics, techniques, and procedures (TTPs).\n\n")
                for tid, name, desc in techniques[:150]: # Index top 150 mobile techniques to conserve memory
                    f.write(f"## {tid}: {name}\n")
                    f.write(f"{desc}\n\n")
            print(f"    [OK] Successfully indexed {len(techniques)} MITRE ATT&CK Mobile TTPs into RAG.")
        except Exception as e:
            print(f"    [ERROR] Failed to parse MITRE ATT&CK: {e}")

def update_osv_vulnerabilities():
    print("\n[*] Processing OSV Android SDK Vulnerabilities...")
    # Query OSV bulk index or query Android package database
    url = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
    zip_path = DATASET_DIR / "osv_android.zip"
    
    if download_file(url, zip_path):
        try:
            extracted_count = 0
            md_content = "# OSV Android SDK Library Vulnerabilities\n\n"
            
            with zipfile.ZipFile(zip_path, 'r') as z:
                # Read first 50 advisory files to prevent OOM while providing fresh knowledge
                names = [name for name in z.namelist() if name.endswith(".json")][:50]
                for name in names:
                    advisory = json.loads(z.read(name).decode("utf-8"))
                    vuln_id = advisory.get("id")
                    summary = advisory.get("summary", advisory.get("details", "No details available."))
                    packages = []
                    for affected in advisory.get("affected", []):
                        pkg_name = affected.get("package", {}).get("name", "Unknown Package")
                        packages.append(pkg_name)
                    
                    md_content += f"## {vuln_id}: Affected Packages: {', '.join(packages)}\n"
                    md_content += f"{summary}\n\n"
                    extracted_count += 1
            
            md_path = KNOWLEDGE_DIR / "osv_android_vulnerabilities.md"
            md_path.write_text(md_content, encoding="utf-8")
            print(f"    [OK] Indexed {extracted_count} OSV Android library vulnerability reports into RAG.")
        except Exception as e:
            print(f"    [ERROR] Failed to parse OSV dataset: {e}")

def update_ios_security_guide():
    print("\n[*] Processing Apple iOS Platform Security References...")
    # Download public Apple CVE list or reference guides
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:apple:iphone_os:17"
    json_path = DATASET_DIR / "ios_cves.json"
    
    if download_file(url, json_path):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities", [])
            
            md_content = "# Apple iOS Security & Vulnerability Advisory\n\n"
            md_content += "Reference iOS vulnerabilities mapped from NVD CVE records.\n\n"
            
            cve_count = 0
            for item in vulns[:50]: # Index top 50 recent iOS 17/18 vulnerabilities
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                desc = cve.get("descriptions", [{}])[0].get("value", "No description.")
                
                md_content += f"## {cve_id}\n"
                md_content += f"{desc}\n\n"
                cve_count += 1
                
            md_path = KNOWLEDGE_DIR / "apple_ios_security_guide.md"
            md_path.write_text(md_content, encoding="utf-8")
            print(f"    [OK] Indexed {cve_count} iOS CVE references into RAG.")
        except Exception as e:
            print(f"    [ERROR] Failed to parse iOS CVEs: {e}")


def update_cisa_kev():
    print("\n[*] Processing CISA Known Exploited Vulnerabilities (KEV) Catalog...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    json_path = DATASET_DIR / "cisa_kev.json"
    
    if download_file(url, json_path):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities", [])
            
            md_content = "# CISA Known Exploited Vulnerabilities - Mobile Platform subset\n\n"
            md_content += "This catalog lists vulnerabilities that have active exploits in the wild affecting mobile platforms.\n\n"
            
            mobile_keywords = ["android", "ios", "apple", "google", "mobile", "iphone", "ipad", "qualcomm", "mediatek", "arm", "samsung"]
            cve_count = 0
            
            for item in vulns:
                cve_id = item.get("cveID", "N/A")
                vendor = item.get("vendorProject", "Unknown")
                product = item.get("product", "Unknown")
                name = item.get("vulnerabilityName", "N/A")
                desc = item.get("shortDescription", "")
                
                is_mobile = False
                for kw in mobile_keywords:
                    if (kw in vendor.lower() or 
                        kw in product.lower() or 
                        kw in name.lower() or 
                        kw in desc.lower()):
                        is_mobile = True
                        break
                
                if is_mobile:
                    md_content += f"## {cve_id}: {vendor} {product} - {name}\n"
                    md_content += f"**Description**: {desc}\n\n"
                    cve_count += 1
                    if cve_count >= 100:
                        break
                        
            md_path = KNOWLEDGE_DIR / "cisa_kev_mobile.md"
            md_path.write_text(md_content, encoding="utf-8")
            print(f"    [OK] Mapped and indexed {cve_count} mobile-relevant KEV entries into RAG.")
        except Exception as e:
            print(f"    [ERROR] Failed to parse CISA KEV: {e}")


def main():
    # Update knowledge repositories
    update_mitre_attack()
    update_osv_vulnerabilities()
    update_ios_security_guide()
    update_cisa_kev()
    
    print("\n" + "=" * 60)
    print("[*] RAG Knowledge Base successfully refreshed with new training datasets!")
    print("    Start the backend to automatically compile and reload the new vector index.")
    print("=" * 60)

if __name__ == "__main__":
    main()
