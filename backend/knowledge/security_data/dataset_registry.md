# Mobile Security Agent (MSA) Dataset Registry

This registry catalogues the complete security dataset collection integrated into the MSA analysis pipeline and Retrieval-Augmented Generation (RAG) knowledge base.

---

## Category 1: Vulnerability Knowledge Base (RAG + M21)

| Dataset | Source URL | Integration Method | Status |
| :--- | :--- | :--- | :--- |
| **CWE Dictionary** | `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` | Automatically parsed XML and indexed. | **Auto-Indexed** (969 entries) |
| **CAPEC Patterns** | `https://capec.mitre.org/data/xml/capec_latest.xml` | Mapped CSV/XML templates loaded. | **Auto-Indexed** (500+ patterns) |
| **NVD CVE Feeds** | `https://github.com/fkie-cad/nvd-json-data-feeds` | Recent/Modified JSON files decompressed. | **Auto-Indexed** (169 active CVEs) |
| **NVD CVE API v2.0** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Query key setup for live CVE mapping. | **Supported** |
| **MITRE ATT&CK Mobile** | `https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json` | Downloaded, parsed, and converted to markdown. | **Auto-Indexed** (190 TTPs) |
| **OSV Library Vulnerabilities** | `https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip` | Automatically ingested and parsed. | **Auto-Indexed** (50 advisories) |

---

## Category 2: Android Malware Datasets & False Positive Calibration

| Dataset | Source URL / Registration | Purpose | Status |
| :--- | :--- | :--- | :--- |
| **AndroZoo** | `https://androzoo.uni.lu/` (Academic Request) | Malicious and benign APK samples. | **Manual-Import** (Requires EULA validation) |
| **DREBIN** | `https://drebin.mlsec.org/` (Academic Request) | Feature validation for static taint rules. | **Manual-Import** (Requires EULA validation) |
| **CICAndMal2017** | `https://www.unb.ca/cic/datasets/andmal2017.html` | Behavioral profile testing for malware families. | **Manual-Import** |
| **CICMalDroid 2020** | `https://www.unb.ca/cic/datasets/maldroid-2020.html` | Adware, banking trojans, and SMS riskware profiling. | **Manual-Import** |

---

## Category 3: LLM Fine-Tuning & Exploits

| Dataset | Source URL | Integration Method | Status |
| :--- | :--- | :--- | :--- |
| **CyberSecEval** | `https://github.com/facebookresearch/CyberSecEval` | Security evaluation benchmark patterns. | **Pre-Trained** (Embedded in LLM weights) |
| **SecureBench / SARD** | `https://samate.nist.gov/SARD/test-suites` | Source code vulnerability patterns. | **Pre-Trained** (Embedded in LLM weights) |
| **Exploit-DB Offline Archive** | `https://github.com/offensive-security/exploitdb` | Exploit payload signatures mapped in engine rules. | **Auto-Indexed** (Offline mapping active) |
| **Security Stack Exchange** | `https://archive.org/details/stackexchange` | Developer remediation Q&A. | **Pre-Trained** (Embedded in LLM weights) |

---

## Category 4: iOS Analysis & Reference Guides

| Dataset | Source URL | Integration Method | Status |
| :--- | :--- | :--- | :--- |
| **VLC / Firefox / Wikipedia** | VLC, Firefox, Wikipedia iOS codebases | Open-source iOS IPA compilation fixtures. | **Supported** (Used for test validation) |
| **Apple Platform Security Guide** | `https://manuals.info.apple.com/MANUALS/1000/MA1902/en_US/apple-platform-security-guide.pdf` | Local PDF mapping for Keychain/ATS rules. | **Auto-Indexed** (Indexed as reference guide) |
| **iOS CVEs** | `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:apple:iphone_os:*` | Downloaded, parsed, and converted to markdown. | **Auto-Indexed** (50 iOS CVEs) |
