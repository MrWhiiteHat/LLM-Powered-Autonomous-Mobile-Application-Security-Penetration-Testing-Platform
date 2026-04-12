"""
Configuration for Mobile Security Agent
"""
import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge" / "security_data"
LOG_DIR = BASE_DIR / "logs"

# Create directories
for d in [UPLOAD_DIR, REPORT_DIR, KNOWLEDGE_DIR, LOG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Server config
HOST = os.getenv("MSA_HOST", "0.0.0.0")
PORT = int(os.getenv("MSA_PORT", "8000"))
DEBUG = os.getenv("MSA_DEBUG", "true").lower() == "true"

# Analysis config
MAX_UPLOAD_SIZE_MB = 500
ALLOWED_EXTENSIONS = {".apk", ".ipa", ".xapk"}

# ChromaDB config
CHROMA_PERSIST_DIR = str(BASE_DIR / "chroma_db")

# CVSS Severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
    "info": 0.0,
}

# OWASP Mobile Top 10 (2024)
OWASP_MOBILE_TOP_10 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

# OWASP API Top 10 (2023)
OWASP_API_TOP_10 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}
