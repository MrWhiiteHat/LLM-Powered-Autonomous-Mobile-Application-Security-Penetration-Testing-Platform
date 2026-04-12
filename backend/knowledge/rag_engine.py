"""
RAG Knowledge Engine
Provides security knowledge retrieval using in-memory search.
"""
import json
from pathlib import Path
from utils.logger import get_logger
from config import KNOWLEDGE_DIR

logger = get_logger("RAGEngine")


# Built-in security knowledge base
SECURITY_KB = {
    "owasp_mobile": {
        "M1": {"name": "Improper Credential Usage", "description": "Hardcoded credentials, improper key management, or credentials in code.", "remediation": "Use secure vaults, never hardcode credentials, implement proper key rotation."},
        "M2": {"name": "Inadequate Supply Chain Security", "description": "Third-party libraries with known vulnerabilities.", "remediation": "Audit dependencies, use SCA tools, keep libraries updated."},
        "M3": {"name": "Insecure Authentication/Authorization", "description": "Weak authentication or missing authorization checks.", "remediation": "Implement MFA, validate sessions server-side, use OAuth 2.0/OIDC."},
        "M4": {"name": "Insufficient Input/Output Validation", "description": "Missing input validation leading to injection attacks.", "remediation": "Validate all inputs, use parameterized queries, encode outputs."},
        "M5": {"name": "Insecure Communication", "description": "Cleartext traffic, missing SSL pinning, weak TLS.", "remediation": "Enforce TLS 1.2+, implement certificate pinning, use network security config."},
        "M6": {"name": "Inadequate Privacy Controls", "description": "Excessive data collection, missing privacy controls.", "remediation": "Minimize data collection, implement privacy by design, comply with GDPR/CCPA."},
        "M7": {"name": "Insufficient Binary Protections", "description": "No obfuscation, anti-tampering, or anti-debugging.", "remediation": "Use ProGuard/R8, implement anti-tampering, detect debuggers and root."},
        "M8": {"name": "Security Misconfiguration", "description": "Debug mode, exported components, insecure defaults.", "remediation": "Disable debug in production, set exported=false, review all configs."},
        "M9": {"name": "Insecure Data Storage", "description": "Sensitive data in SharedPrefs, SQLite, or external storage.", "remediation": "Use EncryptedSharedPreferences, SQLCipher, Android Keystore/iOS Keychain."},
        "M10": {"name": "Insufficient Cryptography", "description": "Weak algorithms, hard-coded keys, improper implementation.", "remediation": "Use AES-256-GCM, proper key management, secure random number generation."},
    },
    "remediation_guides": {
        "hardcoded_secrets": "1. Remove all hardcoded secrets from source code\n2. Use environment variables or secure vaults\n3. Implement secret rotation\n4. Use Android Keystore/iOS Keychain for key storage",
        "certificate_pinning": "1. Implement certificate pinning using OkHttp CertificatePinner (Android) or TrustKit (iOS)\n2. Pin to the leaf or intermediate certificate\n3. Include backup pins\n4. Plan for pin rotation",
        "insecure_storage": "1. Use EncryptedSharedPreferences for Android\n2. Use iOS Keychain with appropriate protection class\n3. Never store sensitive data in external storage\n4. Encrypt SQLite databases with SQLCipher",
        "network_security": "1. Enforce TLS 1.2 minimum\n2. Implement Network Security Config (Android)\n3. Enable App Transport Security (iOS)\n4. Disable cleartext traffic",
    }
}


class RAGEngine:
    def __init__(self):
        self.kb = SECURITY_KB
        logger.info("RAG Engine initialized with built-in security knowledge")

    def query(self, topic: str) -> dict:
        """Query the knowledge base for a topic."""
        topic_lower = topic.lower()
        results = {}

        # Search OWASP Mobile
        for mid, data in self.kb["owasp_mobile"].items():
            if topic_lower in data["name"].lower() or topic_lower in data["description"].lower():
                results[mid] = data

        # Search remediation guides
        for key, guide in self.kb["remediation_guides"].items():
            if topic_lower in key or topic_lower in guide.lower():
                results[f"remediation_{key}"] = guide

        return results

    def get_remediation(self, owasp_id: str) -> str:
        """Get remediation guide for an OWASP category."""
        if owasp_id in self.kb["owasp_mobile"]:
            return self.kb["owasp_mobile"][owasp_id].get("remediation", "No remediation available.")
        return "No remediation guide found."

    def enrich_finding(self, finding: dict) -> dict:
        """Enrich a finding with knowledge base information."""
        enriched = {**finding}
        owasp = finding.get("owasp", "")
        if owasp in self.kb["owasp_mobile"]:
            enriched["owasp_details"] = self.kb["owasp_mobile"][owasp]
            enriched["remediation"] = self.kb["owasp_mobile"][owasp]["remediation"]
        return enriched
