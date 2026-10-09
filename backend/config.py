"""
Configuration for Mobile Security Agent
"""
import os
from pathlib import Path

# Load .env configuration dynamically (zero-dependency custom parser)
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"
if ENV_FILE.exists():
    try:
        for line in ENV_FILE.read_text(encoding="utf-8").split("\n"):
            line = line.split("#")[0].strip()
            if line and "=" in line:
                key, val = line.split("=", 1)
                k = key.strip()
                if k not in os.environ:
                    os.environ[k] = val.strip().strip('"').strip("'")
    except Exception:
        pass

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

# LLM Generative RAG Config
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower() # ollama, lmstudio, openai, nvidia, gemini, none
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5-coder:1.5b" if LLM_PROVIDER == "ollama" else "gpt-4o-mini")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_API_URL = os.getenv("LLM_API_URL", "") # Custom endpoint override
# GPU acceleration default (NVIDIA GeForce GTX 1050 Ti detected)
LLM_FORCE_CPU = os.getenv("LLM_FORCE_CPU", "false").lower() == "true"
LLM_MAX_AUDITS_PER_SCAN = int(os.getenv("LLM_MAX_AUDITS_PER_SCAN", "5"))

