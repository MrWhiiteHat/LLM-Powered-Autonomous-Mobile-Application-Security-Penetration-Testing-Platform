"""
RAG Knowledge Engine
Provides security knowledge retrieval using in-memory TF-IDF vector similarity search.
"""
import os
import re
import math
import json
from pathlib import Path
from utils.logger import get_logger
from config import KNOWLEDGE_DIR
from knowledge.llm_client import LLMClient


logger = get_logger("RAGEngine")

# Default security knowledge datasets for self-population
DEFAULT_OWASP_MOBILE = {
    "M1": {
        "name": "Improper Credential Usage",
        "description": "Hardcoded credentials, improper key management, or credentials in code.",
        "remediation": "1. Utilize a secure credentials vault or external configuration service.\n2. Leverage platform keystores (Android Keystore System or iOS Keychain) to encrypt secrets at rest.\n3. Implement proper key rotation schemes and avoid checking secrets into version control."
    },
    "M2": {
        "name": "Inadequate Supply Chain Security",
        "description": "Third-party libraries with known vulnerabilities, missing verification, or malicious packages.",
        "remediation": "1. Audit third-party dependencies regularly using Software Composition Analysis (SCA) tools.\n2. Maintain an up-to-date Software Bill of Materials (SBOM).\n3. Keep all external dependencies updated to their latest security-patched versions."
    },
    "M3": {
        "name": "Insecure Authentication/Authorization",
        "description": "Weak authentication or missing authorization checks on API endpoints.",
        "remediation": "1. Implement multi-factor authentication (MFA) and strong password complexity requirements.\n2. Always validate sessions and access tokens server-side.\n3. Use standard authorization flows (OAuth 2.0 / OpenID Connect)."
    },
    "M4": {
        "name": "Insufficient Input/Output Validation",
        "description": "Missing input validation leading to injection attacks or data leakage.",
        "remediation": "1. Sanitize and validate all user inputs using strict allowlists.\n2. Utilize parameterized queries (PreparedStatements) for database interactions.\n3. Encode all output data rendered in WebViews to prevent injection."
    },
    "M5": {
        "name": "Insecure Communication",
        "description": "Cleartext traffic, missing SSL pinning, or weak TLS configurations.",
        "remediation": "1. Enforce TLS 1.2 or 1.3 for all connections.\n2. Implement robust SSL/TLS certificate pinning using OkHttp (Android) or TrustKit (iOS).\n3. Block cleartext HTTP traffic via Network Security Config (Android) or App Transport Security (iOS)."
    },
    "M6": {
        "name": "Inadequate Privacy Controls",
        "description": "Excessive data collection, insecure data leakage, or missing privacy controls.",
        "remediation": "1. Minimize data collection to the absolute minimum required for core functionality.\n2. Encrypt sensitive personal identifiable information (PII) before storage or transmission.\n3. Implement user consent flows for data sharing and comply with GDPR/CCPA regulations."
    },
    "M7": {
        "name": "Insufficient Binary Protections",
        "description": "No code obfuscation, anti-tampering, or anti-debugging mechanisms.",
        "remediation": "1. Enable code obfuscation and optimization tools like ProGuard or R8.\n2. Implement runtime self-protection (RASP) to detect emulator execution, debugging hooks, and rooted environments.\n3. Verify application integrity by checking code signatures at runtime."
    },
    "M8": {
        "name": "Security Misconfiguration",
        "description": "Debug mode enabled, insecure exported components, or unsafe default settings.",
        "remediation": "1. Set android:debuggable to false in production manifests.\n2. Explicitly set android:exported to false for components that do not require public access.\n3. Apply strong permission requirements to any exported component that must remain public."
    },
    "M9": {
        "name": "Insecure Data Storage",
        "description": "Sensitive data stored in cleartext inside SQLite databases, SharedPreferences, or external storage.",
        "remediation": "1. Use EncryptedSharedPreferences (Android) or Apple Keychain Services with high protection classes (iOS).\n2. Encrypt local databases using SQLCipher.\n3. Never write sensitive session tokens, credentials, or PII to external storage directories."
    },
    "M10": {
        "name": "Insufficient Cryptography",
        "description": "Use of weak cryptographic algorithms, hard-coded encryption keys, or weak random number generation.",
        "remediation": "1. Implement strong, industry-standard cryptographic primitives such as AES-256-GCM.\n2. Never hardcode encryption keys or initialization vectors; generate them dynamically and store them securely in the hardware keystore.\n3. Use cryptographically secure random number generators (SecureRandom) for all keys, salts, and nonces."
    }
}

DEFAULT_OWASP_API = {
    "API1": {
        "name": "Broken Object Level Authorization",
        "description": "API endpoints are vulnerable because they do not validate if the user has permission to access the requested object ID.",
        "remediation": "1. Implement an authorization check at the object level for every user request.\n2. Use randomized, non-sequential unique identifiers (UUIDs) for object IDs.\n3. Validate session tokens against user permissions before returning resources."
    },
    "API2": {
        "name": "Broken Authentication",
        "description": "Authentication mechanisms are poorly implemented, allowing attackers to brute-force or bypass auth.",
        "remediation": "1. Implement rate limiting and account lockout thresholds on authentication endpoints.\n2. Enforce strong password complexity and utilize multi-factor authentication.\n3. Use standard JWT verification with secure signing keys and appropriate expiration times."
    },
    "API3": {
        "name": "Broken Object Property Level Authorization",
        "description": "Lack of authorization checks when editing or viewing specific fields of an object, leading to mass assignment.",
        "remediation": "1. Restrict API input schemas to only allow editing of authorized fields (use DTOs or input allowlists).\n2. Avoid returning unnecessary properties in API responses; strip out sensitive administrative fields.\n3. Explicitly define which properties are read-only and which are editable."
    },
    "API4": {
        "name": "Unrestricted Resource Consumption",
        "description": "Lack of rate limiting or size limits allows attackers to cause denial of service (DoS) or inflate costs.",
        "remediation": "1. Enforce strict rate limits (e.g., requests per minute) per IP, token, or user account.\n2. Implement limits on request payload size, database query timeouts, and file upload sizes.\n3. Limit the number of records returned in a single paginated API response."
    },
    "API5": {
        "name": "Broken Function Level Authorization",
        "description": "Lack of administrative check on sensitive endpoints allows regular users to perform privileged tasks.",
        "remediation": "1. Implement role-based access control (RBAC) and validate roles server-side.\n2. Deny access to administrative endpoints by default (fail-safe defaults).\n3. Maintain a central authorization module that checks user roles for all API controllers."
    },
    "API6": {
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "Lack of anti-automation protection allows bots to exploit business flows like ticket buying or account creation.",
        "remediation": "1. Implement CAPTCHA or advanced bot-detection systems on sensitive business endpoints.\n2. Profile user request velocity to detect anomalous automation patterns.\n3. Implement device fingerprinting and behavioral analysis to restrict automated bot scripts."
    },
    "API7": {
        "name": "Server Side Request Forgery",
        "description": "API retrieves external resources based on a user-provided URL without validation.",
        "remediation": "1. Validate and sanitize all user-supplied URLs against a strict domain allowlist.\n2. Avoid parsing raw URLs directly; accept pre-defined identifiers or restrict schemas to HTTP/HTTPS.\n3. Block internal network IP ranges (loopback, private subnets) from being requested."
    },
    "API8": {
        "name": "Security Misconfiguration",
        "description": "Verbose error messages, debug endpoints enabled, or missing security headers.",
        "remediation": "1. Disable debug logs, stack traces, and verbose error messages in production environments.\n2. Implement strong security headers (e.g., Content-Security-Policy, X-Content-Type-Options).\n3. Keep all third-party dependencies and frameworks updated to stable, patched versions."
    },
    "API9": {
        "name": "Improper Inventory Management",
        "description": "Old API versions (v1, beta) or unlisted endpoints remain active and unpatched.",
        "remediation": "1. Document and inventory all API endpoints, parameters, and versions.\n2. Deprecate and shut down old, unpatched API versions as soon as possible.\n3. Implement strict access control lists on staging, testing, and beta environments."
    },
    "API10": {
        "name": "Unsafe Consumption of APIs",
        "description": "API trusts data received from third-party APIs without validation, leading to injection or logic bypass.",
        "remediation": "1. Sanitize and validate all data received from external integrations and third-party APIs.\n2. Apply the principle of least privilege when granting permissions to external API tokens.\n3. Implement strict timeout thresholds and fallback logic for third-party integrations."
    }
}

DEFAULT_CWE_REMEDIATIONS = {
    "CWE-78": {
        "name": "OS Command Injection",
        "remediation": "1. Validate and sanitize all inputs before executing system commands.\n2. Avoid using shell execution; use secure, typed APIs (e.g., ProcessBuilder on Android with explicit argument lists).\n3. Implement strict character allowlists for any input passed to commands."
    },
    "CWE-89": {
        "name": "SQL Injection",
        "remediation": "1. Use parameterized queries (PreparedStatement) for all database operations.\n2. Never concatenate untrusted inputs directly into raw SQL strings.\n3. Utilize secure ORM libraries with built-in parameterization."
    },
    "CWE-79": {
        "name": "Cross-site Scripting / WebView Injection",
        "remediation": "1. Disable JavaScript in WebViews if not strictly required (webView.getSettings().setJavaScriptEnabled(false)).\n2. Implement a robust Content Security Policy (CSP).\n3. Sanitize and HTML-encode any user inputs rendered inside the WebView."
    },
    "CWE-470": {
        "name": "Unsafe Reflection / Dynamic Class Loading",
        "remediation": "1. Avoid using Class.forName() with dynamically resolved or user-controlled string arguments.\n2. Use a hardcoded allowlist to validate class names before instantiation.\n3. Keep reflection strictly static and compile-time checked where possible."
    },
    "CWE-494": {
        "name": "Dynamic Class Loading of Untrusted Code",
        "remediation": "1. Avoid downloading and executing external dex/jar files or bundles at runtime.\n2. If dynamic loading is unavoidable, verify the integrity of the downloaded file using strong cryptographic signatures (e.g., SHA-256) against a pre-signed trusted key.\n3. Ensure files are downloaded over secure HTTPS channels with certificate pinning."
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "remediation": "1. Never implement custom cryptography or proprietary XOR-based obfuscation loops for sensitive data.\n2. Utilize standard, industry-proven cryptographic libraries and algorithms (e.g., AES-256-GCM via Android Keystore / iOS Keychain).\n3. Avoid 'roll-your-own' security controls."
    },
    "CWE-927": {
        "name": "Use of Implicit Intent for Sensitive Communication / Deep Link Redirect",
        "remediation": "1. Avoid parsing raw query parameters from custom deep-link schemes directly into Intent launches.\n2. Validate and sanitize all incoming deep-link parameters using a strict allowlist.\n3. Use explicit intents instead of implicit intents for internal app communication."
    },
    "CWE-506": {
        "name": "Embedded Malicious Code / Behavioral Profiling",
        "remediation": "1. Audit all third-party dependencies and transitive dependencies for anomalous behaviors.\n2. Implement runtime self-protection (RASP) to detect tampering, debugging, and hook frameworks.\n3. Enforce strict principle of least privilege: request only permissions that are strictly necessary for core functionality."
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "remediation": "1. Encrypt all sensitive data before writing it to local storage.\n2. Use EncryptedSharedPreferences (Android) or Keychain Services with high protection classes (iOS).\n3. Do not store sensitive tokens, credit cards, or passwords in plain text databases."
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "remediation": "1. Disable verbose debug logging and ensure no sensitive variables are printed to Logcat or console.\n2. Mask sensitive fields (e.g., credit card numbers, passwords) in UI and logs.\n3. Prevent application screenshots by setting FLAG_SECURE on Android window managers."
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "remediation": "1. Remove all hardcoded API keys, private keys, passwords, and tokens from source code and assets.\n2. Retrieve keys dynamically from a secure remote configuration server using runtime authentication.\n3. Restrict and scope client-side API keys using referrer restrictions, package name checks, or IP allowlists."
    },
    "CWE-295": {
        "name": "Improper Certificate Validation / Missing SSL Pinning",
        "remediation": "1. Implement robust SSL/TLS certificate pinning using TrustKit (iOS) or OkHttp CertificatePinner (Android).\n2. Never bypass default trust managers or implement empty X509TrustManager methods that trust all certificates.\n3. Pin against the intermediate or root CA certificate to allow certificates to rotate safely."
    },
    "CWE-319": {
        "name": "Cleartext Transmission of Sensitive Information",
        "remediation": "1. Enforce HTTPS for all network communication and block HTTP fallback.\n2. Set cleartextTrafficPermitted to false in Android Network Security Config.\n3. Enable App Transport Security (ATS) with NSAllowsArbitraryLoads set to false in iOS Info.plist."
    },
    "CWE-693": {
        "name": "Protection Mechanism Failure / Missing Protections",
        "remediation": "1. Integrate third-party integrity checks to detect Frida, Xposed, Magisk, or substrate hooking tools.\n2. Implement anti-debugger checks using ptrace or platform APIs.\n3. Detect rooted or jailbroken operating system environments and gracefully terminate sensitive app flows."
    },
    "CWE-922": {
        "name": "Insecure Storage of Sensitive Information",
        "remediation": "1. Restrict local file permissions to private mode (MODE_PRIVATE).\n2. Encrypt SQLite databases with SQLCipher.\n3. Never store credentials, tokens, or encryption keys in plain text files in the application's cache."
    },
    "CWE-925": {
        "name": "Improper Verification of Intent Source",
        "remediation": "1. Validate and sanitize all incoming intents and extras to ensure they come from authorized application modules.\n2. Use pending intents with explicit configurations when passing execution contexts to third parties.\n3. Keep critical application receivers closed or protected by custom signature permissions."
    },
    "CWE-926": {
        "name": "Improper Export of Android Application Components",
        "remediation": "1. Set android:exported to false for all activities, services, receivers, and providers that do not require external integration.\n2. For components that must be exported, enforce custom signature-level permissions so only your certified apps can interact with them.\n3. Validate all incoming intents to exported components before parsing parameter data."
    },
    "CWE-22": {
        "name": "Path Traversal / Zip Slip",
        "remediation": "1. Validate that destination file paths fall within the target directory boundary before extracting archives (e.g., check canonicalPath starts with destination directory).\n2. Sanitize user-controlled file paths, removing sequences like '../' or '..\\'.\n3. Use platform APIs with built-in path resolution limits."
    },
    "CWE-215": {
        "name": "Insertion of Sensitive Info into Debug Code",
        "remediation": "1. Ensure all debugging utilities, debug logs, and diagnostic assertions are disabled or removed in release builds.\n2. Configure ProGuard or R8 rules to automatically strip logging calls (e.g., Log.d, Log.v) during compilation.\n3. Verify that the android:debuggable flag is set to false."
    },
    "CWE-250": {
        "name": "Execution with Unnecessary Privileges",
        "remediation": "1. Minimize application permission requirements to only those strictly necessary for core operations.\n2. Use granular Android runtime permissions and iOS usage descriptions rather than requesting broad administrative privileges.\n3. Avoid executing command tasks under root contexts."
    },
    "CWE-276": {
        "name": "Incorrect Default Permissions",
        "remediation": "1. Restrict internal database and configuration file permissions so they are only readable by the application owner process (MODE_PRIVATE).\n2. Avoid using world-readable or world-writable flags on application files.\n3. Verify file permissions dynamically on system creation."
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "remediation": "1. Enforce robust server-side token validation (such as cryptographically signed JWTs) for every API request.\n2. Implement local biometric authentication (Android BiometricPrompt, iOS LocalAuthentication) with keystore-backed key verification.\n3. Avoid relying solely on client-side state flags for auth checks."
    },
    "CWE-311": {
        "name": "Missing Encryption of Sensitive Data",
        "remediation": "1. Use standard encryption primitives (e.g., AES-GCM or RSA-OAEP) to secure sensitive payloads at rest and in transit.\n2. Never write plaintext credentials, session tokens, or personally identifiable info (PII) to local storage.\n3. Leverage secure hardware keys for encryption operations."
    },
    "CWE-321": {
        "name": "Use of Hard-coded Cryptographic Key",
        "remediation": "1. Remove hardcoded encryption keys, initialization vectors, and salt values from code and property files.\n2. Generate cryptographic keys dynamically at runtime and store them in secure hardware vaults (Android Keystore, iOS Keychain).\n3. Use key derivation functions (like PBKDF2) to derive keys from passwords dynamically."
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "remediation": "1. Use modern cryptographic algorithms with sufficient key lengths (e.g., AES-256 instead of DES/3DES/AES-128).\n2. Avoid using weak hash algorithms like MD5 or SHA-1 for cryptographic verification; transition to SHA-256 or SHA-3.\n3. Choose strong, random initialization vectors."
    },
    "CWE-524": {
        "name": "Use of Cache Containing Sensitive Information",
        "remediation": "1. Disable WebView credential caching and autocomplete mechanisms when handling sensitive user logins.\n2. Clear application memory caches, temporary files, and cookies during user logout events.\n3. Prevent sensitive data from being written to temporary cache files."
    },
    "CWE-530": {
        "name": "Exposure of Sensitive Information Through Accessible Data",
        "remediation": "1. Avoid storing sensitive application records in publicly shared directories (e.g., Android External SD Card storage).\n2. Always verify that directories used to cache transient data are marked private to the app sandbox.\n3. Run regular audits on file paths utilized by background tasks."
    },
    "CWE-532": {
        "name": "Insertion of Sensitive Information into Log File",
        "remediation": "1. Review code logging commands and ensure no authentication tokens, passwords, or PII are printed to system logs.\n2. Implement a logging wrapper that strips or masks potential secrets before outputting to Logcat or console logs.\n3. Strip logging statements completely from production binaries using compiler optimizer configuration."
    },
    "CWE-598": {
        "name": "Use of GET Request Method With Sensitive Query Strings",
        "remediation": "1. Pass sensitive credentials, authentication tokens, and user parameters inside POST/PUT request bodies instead of GET query parameters.\n2. Restrict backend route logging to prevent query parameters from being stored in cleartext server logs.\n3. Implement HTTPS to protect transit headers."
    },
    "CWE-639": {
        "name": "Authorization Bypass Through User-Controlled Key",
        "remediation": "1. Validate access rights server-side by checking the logged-in session token against requested resource IDs (prevent Insecure Direct Object Reference).\n2. Use non-predictable resource keys (such as UUIDs) to prevent simple identifier enumeration.\n3. Never trust client-provided permission claims."
    },
    "CWE-749": {
        "name": "Exposed Dangerous Method or Function",
        "remediation": "1. Mark sensitive native methods or helper utilities as private to prevent access by unauthorized classes.\n2. Restrict JavaScript interface exposures in WebViews (addJavascriptInterface) to only trusted functions and domains.\n3. Use security access modifiers to encapsulate dangerous routines."
    },
    "CWE-770": {
        "name": "Allocation of Resources Without Limits or Throttling",
        "remediation": "1. Enforce server-side rate limiting on all API endpoints using token bucket or leaky bucket algorithms.\n2. Set maximum payload limits for incoming requests and configure client-side request timeout boundaries.\n3. Limit the maximum size of dynamic memory buffers."
    },
    "CWE-919": {
        "name": "Weaknesses in Mobile Applications",
        "remediation": "1. Follow standard secure mobile coding guidelines (such as the OWASP Mobile Application Security Verification Standard).\n2. Implement routine static and dynamic application security reviews in development cycles.\n3. Verify third-party mobile SDKs for compliance."
    },
    "CWE-939": {
        "name": "Improper Authorization in Handler for Custom URL Scheme",
        "remediation": "1. Implement strict validation and origin checking on incoming custom URL scheme data.\n2. Avoid using custom URL parameters to execute actions directly without secondary user confirmation.\n3. Transition to standard Universal Links (iOS) or App Links (Android) for secure deep linking."
    },
    "CWE-1059": {
        "name": "Insufficient Technical Documentation",
        "remediation": "1. Document all API contracts, schemas, permissions, and security controls within the codebase.\n2. Provide developer documentation outlining secure integration guidelines for internal frameworks.\n3. Maintain clean, well-commented source modules."
    }
}


DEFAULT_REMEDIATION_GUIDES = {
    "hardcoded_secrets": "1. Remove all hardcoded secrets from source code.\n2. Use environment variables or secure vaults.\n3. Implement secret rotation.\n4. Use Android Keystore/iOS Keychain for key storage.",
    "certificate_pinning": "1. Implement certificate pinning using OkHttp CertificatePinner (Android) or TrustKit (iOS).\n2. Pin to the leaf or intermediate certificate.\n3. Include backup pins.\n4. Plan for pin rotation.",
    "insecure_storage": "1. Use EncryptedSharedPreferences for Android.\n2. Use iOS Keychain with appropriate protection class.\n3. Never store sensitive data in external storage.\n4. Encrypt SQLite databases with SQLCipher.",
    "network_security": "1. Enforce TLS 1.2 minimum.\n2. Implement Network Security Config (Android).\n3. Enable App Transport Security (iOS).\n4. Disable cleartext traffic."
}

# ---
# ADVANCED RAG RETRIEVAL PIPELINE v3.0
# 8-component hybrid retrieval: TF-IDF + BM25 + Query Expansion + Knowledge
# Graph + Reciprocal Rank Fusion + Cross-Encoder Re-ranking + Contextual
# Compression + Multi-Source Enrichment
# All pure Python --- zero external dependencies --- 100% offline
# ---

# Source authority weights --- higher = more trusted in final ranking
SOURCE_AUTHORITY = {
    "owasp_mobile": 1.30,
    "owasp_api": 1.20,
    "cwe": 1.25,
    "cwe_catalog": 1.00,
    "masvs": 1.15,
    "capec": 1.10,
    "cve": 0.90,
    "remediation_guide": 1.10,
    "markdown": 0.80,
}


class SimpleTFIDF:
    """
    Enhanced TF-IDF engine with bigram phrase indexing.
    Supports unigram + bigram tokens for better multi-word term matching
    (e.g., 'sql_injection', 'certificate_pinning').
    Requires zero external C/C++ compiled packages.
    """
    def __init__(self):
        self.documents = []  # list of str
        self.metadata = []   # list of dict (document properties)
        self.vocab = []      # list of unique tokens
        self.idf = {}        # token -> idf score
        self.tfidf_matrix = [] # list of dict (token -> tfidf score)

    def tokenize(self, text: str) -> list:
        """Tokenize text into unigrams and bigrams for phrase-level matching."""
        unigrams = re.findall(r'\b[a-zA-Z0-9\-]{2,}\b', text.lower())
        # Generate bigrams for phrase matching (e.g., "sql injection" -> "sql_injection")
        bigrams = []
        for i in range(len(unigrams) - 1):
            bigrams.append(f"{unigrams[i]}_{unigrams[i+1]}")
        return unigrams + bigrams

    def fit_transform(self, documents: list, metadata: list):
        """Build the TF-IDF vocabulary, compute IDF scores, and build the document matrix."""
        self.documents = documents
        self.metadata = metadata
        
        doc_counts = len(documents)
        if doc_counts == 0:
            return
            
        # 1. Count Term Frequencies (TF) and Document Frequencies (DF)
        doc_tfs = []
        df = {}
        
        for doc in documents:
            tokens = self.tokenize(doc)
            tf = {}
            for token in tokens:
                tf[token] = tf.get(token, 0) + 1
            doc_tfs.append(tf)
            for token in tf.keys():
                df[token] = df.get(token, 0) + 1
                
        # 2. Calculate IDF scores with smoothing
        self.vocab = list(df.keys())
        self.idf = {}
        for token, count in df.items():
            self.idf[token] = math.log(1 + (doc_counts / count))
            
        # 3. Calculate TF-IDF vectors
        self.tfidf_matrix = []
        for tf in doc_tfs:
            vector = {}
            for token, tf_val in tf.items():
                vector[token] = tf_val * self.idf[token]
            self.tfidf_matrix.append(vector)

    def cosine_similarity(self, vec1: dict, vec2: dict) -> float:
        """Calculate the cosine similarity between two sparse vector dictionaries."""
        dot_product = 0.0
        for token, val in vec1.items():
            if token in vec2:
                dot_product += val * vec2[token]
                
        mag1 = math.sqrt(sum(v * v for v in vec1.values()))
        mag2 = math.sqrt(sum(v * v for v in vec2.values()))
        
        if mag1 == 0.0 or mag2 == 0.0:
            return 0.0
        return dot_product / (mag1 * mag2)

    def search(self, query_text: str, top_n: int = 3) -> list:
        """Run a similarity search query and return ranked document matches."""
        query_tokens = self.tokenize(query_text)
        if not query_tokens or not self.tfidf_matrix:
            return []
            
        # Calculate query TF-IDF vector
        query_tf = {}
        for token in query_tokens:
            query_tf[token] = query_tf.get(token, 0) + 1
            
        query_vec = {}
        for token, tf_val in query_tf.items():
            if token in self.idf:
                query_vec[token] = tf_val * self.idf[token]
                
        if not query_vec:
            return []
            
        # Calculate similarities
        results = []
        for i, doc_vec in enumerate(self.tfidf_matrix):
            sim = self.cosine_similarity(query_vec, doc_vec)
            if sim > 0.02:  # Lowered threshold for hybrid pipeline
                results.append((i, sim))
                
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_n]

    def search_formatted(self, query_text: str, top_n: int = 3) -> list:
        """Search and return formatted result dicts (backward compatible)."""
        raw = self.search(query_text, top_n)
        formatted = []
        for idx, score in raw:
            formatted.append({
                "metadata": self.metadata[idx],
                "content": self.documents[idx],
                "score": round(score, 4)
            })
        return formatted


class BM25Retriever:
    """
    Okapi BM25 ranking algorithm â€” superior to raw TF-IDF for information retrieval.
    Uses term-frequency saturation to prevent long documents from dominating results.
    Parameters: k1=1.5 (term frequency saturation), b=0.75 (length normalization).
    """
    def __init__(self, k1=1.5, b=0.75):
        self.k1 = k1
        self.b = b
        self.doc_count = 0
        self.avg_dl = 1.0
        self.doc_lengths = []
        self.doc_term_freqs = []  # list of {token: count}
        self.doc_freqs = {}       # token -> number of docs containing it

    def tokenize(self, text: str) -> list:
        """Tokenize text into unigrams and bigrams."""
        unigrams = re.findall(r'\b[a-zA-Z0-9\-]{2,}\b', text.lower())
        bigrams = [f"{unigrams[i]}_{unigrams[i+1]}" for i in range(len(unigrams) - 1)]
        return unigrams + bigrams

    def fit(self, documents: list):
        """Build the BM25 index from a list of document strings."""
        self.doc_count = len(documents)
        if self.doc_count == 0:
            return

        self.doc_term_freqs = []
        self.doc_freqs = {}
        self.doc_lengths = []

        for doc in documents:
            tokens = self.tokenize(doc)
            self.doc_lengths.append(len(tokens))
            tf = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
            self.doc_term_freqs.append(tf)
            for t in tf:
                self.doc_freqs[t] = self.doc_freqs.get(t, 0) + 1

        total_len = sum(self.doc_lengths)
        self.avg_dl = total_len / self.doc_count if self.doc_count else 1.0

    def score(self, query_text: str, top_n: int = 20) -> list:
        """Score all documents against the query. Returns list of (doc_index, bm25_score)."""
        tokens = self.tokenize(query_text)
        if not tokens or not self.doc_term_freqs:
            return []

        scores = []
        for i, tf in enumerate(self.doc_term_freqs):
            s = 0.0
            dl = self.doc_lengths[i]
            for t in tokens:
                if t not in tf:
                    continue
                f = tf[t]
                df = self.doc_freqs.get(t, 0)
                # IDF component with floor to avoid negative values
                idf = max(math.log((self.doc_count - df + 0.5) / (df + 0.5) + 1.0), 0.0)
                # BM25 TF normalization
                tf_norm = (f * (self.k1 + 1.0)) / (f + self.k1 * (1.0 - self.b + self.b * dl / self.avg_dl))
                s += idf * tf_norm
            if s > 0:
                scores.append((i, s))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_n]


class SecurityQueryExpander:
    """
    Domain-specific query expansion using a curated mobile security synonym thesaurus.
    Automatically appends related terms to queries before retrieval.
    """

    THESAURUS = {
        "sql injection": ["sqli", "database injection", "sql query manipulation", "rawquery"],
        "xss": ["cross-site scripting", "script injection", "webview injection"],
        "hardcoded": ["hard-coded", "embedded credential", "static credential", "hardcoded key"],
        "cleartext": ["plaintext", "unencrypted", "plain text", "clear text"],
        "ssl": ["tls", "certificate", "https", "transport security", "ssl pinning"],
        "root": ["jailbreak", "rooted", "superuser", "su binary", "magisk"],
        "debug": ["debuggable", "debugging", "debugger", "isdebuggable"],
        "storage": ["sharedpreferences", "userdefaults", "sqlite", "database", "keychain", "keystore"],
        "permission": ["privilege", "access control", "authorization", "dangerous permission"],
        "crypto": ["cryptography", "encryption", "cipher", "aes", "rsa", "des", "md5"],
        "obfuscation": ["proguard", "r8", "code protection", "minification", "dexguard"],
        "webview": ["web view", "javascript interface", "loadurl", "addjavascriptinterface"],
        "api key": ["secret key", "access token", "bearer token", "credential", "stripe key"],
        "certificate pinning": ["ssl pinning", "tls pinning", "cert pinning", "trustmanager"],
        "malware": ["spyware", "trojan", "rat", "backdoor", "malicious code"],
        "injection": ["command injection", "code injection", "os injection", "taint flow"],
        "authentication": ["auth", "login", "session", "token validation", "biometric"],
        "network": ["http", "https", "cleartext traffic", "transport layer", "network security config"],
        "backup": ["allowbackup", "data backup", "android backup"],
        "exported": ["android exported", "component exported", "intent filter", "exported activity"],
        "deep link": ["custom url scheme", "app link", "universal link", "intent scheme"],
        "reflection": ["class forname", "dynamic loading", "dexclassloader", "unsafe reflection"],
        "random": ["securerandom", "java util random", "weak random", "prng"],
        "intent": ["implicit intent", "explicit intent", "broadcast", "pendingintent"],
        "binary protection": ["anti-tamper", "anti-debug", "integrity check", "code signing"],
    }

    def expand(self, query: str) -> str:
        """Return expanded query string with relevant synonyms appended."""
        import re as _re
        q_lower = query.lower()
        expansions = set()

        for key, synonyms in self.THESAURUS.items():
            # Forward: key found as whole words in query --- add synonyms
            if _re.search(r'\b' + _re.escape(key) + r'\b', q_lower):
                expansions.update(synonyms)
            # Reverse: synonym found as whole words in query --- add key + other synonyms
            for syn in synonyms:
                if _re.search(r'\b' + _re.escape(syn) + r'\b', q_lower):
                    expansions.add(key)
                    expansions.update(s for s in synonyms if s != syn)

        if expansions:
            return query + " " + " ".join(expansions)
        return query


class SecurityKnowledgeGraph:
    """
    Builds CWEâ†’CAPECâ†’OWASP taxonomy relationships for graph-augmented retrieval.
    When a finding references a CWE, the graph can traverse to related CAPEC
    attack patterns and OWASP categories, pulling sibling weaknesses.
    """

    # Static CWE --- OWASP Mobile Top 10 mapping
    CWE_TO_OWASP = {
        "CWE-798": "M1", "CWE-321": "M1",
        "CWE-312": "M9", "CWE-922": "M9", "CWE-311": "M9",
        "CWE-530": "M9", "CWE-524": "M9", "CWE-532": "M9",
        "CWE-319": "M5", "CWE-295": "M5",
        "CWE-326": "M10", "CWE-327": "M10",
        "CWE-693": "M7", "CWE-494": "M7", "CWE-506": "M7",
        "CWE-215": "M8", "CWE-926": "M8", "CWE-925": "M8",
        "CWE-276": "M8", "CWE-250": "M8", "CWE-749": "M8",
        "CWE-770": "M8", "CWE-919": "M8",
        "CWE-287": "M3", "CWE-639": "M3",
        "CWE-79": "M4", "CWE-78": "M4", "CWE-89": "M4",
        "CWE-22": "M4", "CWE-470": "M4", "CWE-927": "M4", "CWE-939": "M4",
        "CWE-200": "M6", "CWE-598": "M6",
    }

    def __init__(self):
        self.cwe_to_capec = {}   # CWE-ID -> [CAPEC-IDs]
        self.capec_to_cwe = {}   # CAPEC-ID -> [CWE-IDs]
        self.cwe_to_owasp = dict(self.CWE_TO_OWASP)
        self.owasp_to_cwes = {}  # OWASP-ID -> [CWE-IDs]

        # Build reverse OWASP---CWE index
        for cwe, owasp in self.CWE_TO_OWASP.items():
            self.owasp_to_cwes.setdefault(owasp, []).append(cwe)

    def add_capec_mapping(self, capec_id: str, related_cwes: list):
        """Register a CAPECâ†’CWE relationship edge."""
        for cwe_id in related_cwes:
            self.cwe_to_capec.setdefault(cwe_id, []).append(capec_id)
            self.capec_to_cwe.setdefault(capec_id, []).append(cwe_id)

    def get_related_ids(self, doc_id: str, depth: int = 1) -> set:
        """Traverse the taxonomy graph to find related document IDs."""
        related = set()

        if doc_id.startswith("CWE-"):
            # CWE --- OWASP Mobile category
            owasp = self.cwe_to_owasp.get(doc_id)
            if owasp:
                related.add(owasp)
            # CWE --- CAPEC attack patterns
            for capec in self.cwe_to_capec.get(doc_id, []):
                related.add(capec)
            # Sibling CWEs sharing the same OWASP category
            if owasp and depth > 0:
                for sibling in self.owasp_to_cwes.get(owasp, []):
                    if sibling != doc_id:
                        related.add(sibling)

        elif doc_id.startswith("M") or doc_id.startswith("API"):
            # OWASP --- all mapped CWEs
            for cwe in self.owasp_to_cwes.get(doc_id, []):
                related.add(cwe)

        elif doc_id.startswith("CAPEC-"):
            # CAPEC --- related CWEs
            for cwe in self.capec_to_cwe.get(doc_id, []):
                related.add(cwe)

        return related

    @property
    def edge_count(self) -> int:
        """Total number of relationship edges in the graph."""
        count = len(self.cwe_to_owasp)
        count += sum(len(v) for v in self.cwe_to_capec.values())
        return count


class HybridRetriever:
    """
    Combines BM25 + TF-IDF candidate lists using Reciprocal Rank Fusion (RRF).
    RRF formula: score(d) = Î£ 1/(k + rank_i(d)) across all retrievers.
    Applies source authority boosting to prefer high-trust knowledge sources.
    """

    def __init__(self, tfidf: SimpleTFIDF, bm25: BM25Retriever,
                 documents: list, metadata: list, rrf_k: int = 60):
        self.tfidf = tfidf
        self.bm25 = bm25
        self.documents = documents
        self.metadata = metadata
        self.rrf_k = rrf_k

    def search(self, query_text: str, top_n: int = 15) -> list:
        """Run hybrid retrieval with RRF fusion and source authority boosting."""
        # 1. TF-IDF retrieval (top-20 candidates)
        tfidf_ranked = self.tfidf.search(query_text, top_n=20)

        # 2. BM25 retrieval (top-20 candidates)
        bm25_ranked = self.bm25.score(query_text, top_n=20)

        # 3. Reciprocal Rank Fusion
        rrf_scores = {}

        for rank, (idx, _score) in enumerate(tfidf_ranked):
            rrf_scores[idx] = rrf_scores.get(idx, 0.0) + 1.0 / (self.rrf_k + rank + 1)

        for rank, (idx, _score) in enumerate(bm25_ranked):
            rrf_scores[idx] = rrf_scores.get(idx, 0.0) + 1.0 / (self.rrf_k + rank + 1)

        # 4. Apply source authority boosting
        for idx in rrf_scores:
            source_type = self.metadata[idx].get("type", "markdown")
            authority = SOURCE_AUTHORITY.get(source_type, 1.0)
            rrf_scores[idx] *= authority

        # 5. Sort by fused score
        ranked = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)

        results = []
        for idx, rrf_score in ranked[:top_n]:
            results.append({
                "metadata": self.metadata[idx],
                "content": self.documents[idx],
                "score": round(rrf_score, 6)
            })

        return results


class CrossEncoderReranker:
    """
    Lightweight second-pass re-ranker using:
    1. Jaccard token overlap between query and document
    2. Exact bigram phrase matching bonus
    3. CWE/OWASP/CAPEC ID match bonus
    4. Original retrieval score preservation
    """

    @staticmethod
    def _tokenize(text: str) -> set:
        return set(re.findall(r'\b[a-zA-Z0-9\-]{2,}\b', text.lower()))

    def rerank(self, query: str, candidates: list, top_n: int = 5) -> list:
        """Re-rank candidates using multi-signal scoring."""
        query_tokens = self._tokenize(query)
        query_lower = query.lower()

        scored = []
        for cand in candidates:
            content = cand.get("content", "")
            content_lower = content.lower()
            content_tokens = self._tokenize(content)

            # Signal 1: Jaccard token overlap
            intersection = query_tokens & content_tokens
            union = query_tokens | content_tokens
            jaccard = len(intersection) / len(union) if union else 0.0

            # Signal 2: Exact bigram phrase match bonus
            phrase_bonus = 0.0
            words = query_lower.split()
            for i in range(len(words) - 1):
                bigram = f"{words[i]} {words[i+1]}"
                if bigram in content_lower:
                    phrase_bonus += 0.15

            # Signal 3: Explicit ID match bonus (CWE-XXX, CAPEC-XXX, etc.)
            id_bonus = 0.0
            id_patterns = re.findall(
                r'(CWE-\d+|CAPEC-\d+|CVE-\d+-\d+|M\d+|API\d+)',
                query, re.IGNORECASE
            )
            for pat in id_patterns:
                if pat.upper() in content.upper():
                    id_bonus += 0.30

            # Signal 4: Original retrieval score
            original = cand.get("score", 0.0)

            # Weighted composite score
            final = (0.25 * jaccard) + (0.20 * phrase_bonus) + (0.25 * id_bonus) + (0.30 * original)

            scored.append({**cand, "rerank_score": round(final, 4)})

        scored.sort(key=lambda x: x["rerank_score"], reverse=True)
        return scored[:top_n]


class ContextualCompressor:
    """
    Extracts the most query-relevant sentences from retrieved documents,
    reducing noise and improving the quality of attached remediation context.
    """

    @staticmethod
    def compress(query: str, document_text: str, max_sentences: int = 3) -> str:
        """Extract the most relevant sentences from a document."""
        query_tokens = set(re.findall(r'\b[a-zA-Z0-9\-]{2,}\b', query.lower()))
        if not query_tokens:
            return document_text[:500]

        # Split on sentence boundaries and numbered list items
        sentences = re.split(r'(?<=[.!?])\s+|\n(?=\d+\.)', document_text)
        sentences = [s.strip() for s in sentences if s.strip() and len(s.strip()) > 10]

        if not sentences:
            return document_text[:500]

        scored = []
        for sent in sentences:
            sent_tokens = set(re.findall(r'\b[a-zA-Z0-9\-]{2,}\b', sent.lower()))
            overlap = len(query_tokens & sent_tokens)
            coverage = overlap / max(len(query_tokens), 1)
            scored.append((sent, coverage))

        scored.sort(key=lambda x: x[1], reverse=True)
        top = [s[0] for s in scored[:max_sentences] if s[1] > 0]

        if not top:
            # Fallback: return first sentences
            return " ".join(sentences[:max_sentences])

        return " ".join(top)


class RAGEngine:
    """
    Advanced RAG Knowledge Engine v3.0
    Multi-strategy retrieval pipeline:
      1. SecurityQueryExpander â€” synonym-based query expansion
      2. SimpleTFIDF â€” bigram-enhanced TF-IDF retrieval
      3. BM25Retriever â€” Okapi BM25 ranking
      4. HybridRetriever â€” Reciprocal Rank Fusion of TF-IDF + BM25
      5. SecurityKnowledgeGraph â€” CWEâ†’CAPECâ†’OWASP graph traversal
      6. CrossEncoderReranker â€” multi-signal second-pass re-ranking
      7. ContextualCompressor â€” query-relevant sentence extraction
      8. Multi-source enrichment â€” top-3 contexts from different sources
    """
    def __init__(self):
        self.knowledge_dir = KNOWLEDGE_DIR
        self.kb = {
            "owasp_mobile": {},
            "owasp_api": {},
            "cwe": {},
            "remediation_guides": {},
            "masvs": {},
            "capec": {},
            "cve": {},
            "cwe_catalog": {}
        }

        # Core retrieval engines
        self.vector_store = SimpleTFIDF()
        self.bm25_store = BM25Retriever()
        self.hybrid_retriever = None  # Initialized after index build

        # Advanced pipeline components
        self.query_expander = SecurityQueryExpander()
        self.knowledge_graph = SecurityKnowledgeGraph()
        self.reranker = CrossEncoderReranker()
        self.compressor = ContextualCompressor()
        self.llm_client = LLMClient()


        # Document corpus (shared between TF-IDF and BM25)
        self._documents = []
        self._metadata = []

        # 1. Initialize and self-populate directories/files if missing
        self._self_populate()

        
        # 2. Load all documents from disk
        self._load_knowledge_base()
        self._load_external_datasets()
        
        # 3. Compile documents into the TF-IDF vector index
        self._build_vector_index()

    def _self_populate(self):
        """Write production-grade security rules to the knowledge directory if empty."""
        try:
            self.knowledge_dir.mkdir(parents=True, exist_ok=True)
            
            files_to_populate = {
                "owasp_mobile_rules.json": DEFAULT_OWASP_MOBILE,
                "owasp_api_rules.json": DEFAULT_OWASP_API,
                "cwe_remediations.json": DEFAULT_CWE_REMEDIATIONS,
                "remediation_guides.json": DEFAULT_REMEDIATION_GUIDES
            }
            
            for filename, data in files_to_populate.items():
                filepath = self.knowledge_dir / filename
                if not filepath.exists():
                    filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
                    logger.info(f"Self-populated missing knowledge file: {filename}")
        except Exception as e:
            logger.error(f"Error self-populating RAG knowledge: {e}")

    def _load_knowledge_base(self):
        """Read all JSON and Markdown knowledge files from KNOWLEDGE_DIR."""
        try:
            # Load OWASP Mobile Rules
            mobile_path = self.knowledge_dir / "owasp_mobile_rules.json"
            if mobile_path.exists():
                self.kb["owasp_mobile"] = json.loads(mobile_path.read_text(encoding="utf-8"))
                
            # Load OWASP API Rules
            api_path = self.knowledge_dir / "owasp_api_rules.json"
            if api_path.exists():
                self.kb["owasp_api"] = json.loads(api_path.read_text(encoding="utf-8"))
                
            # Load CWE Remediations
            cwe_path = self.knowledge_dir / "cwe_remediations.json"
            if cwe_path.exists():
                self.kb["cwe"] = json.loads(cwe_path.read_text(encoding="utf-8"))
                
            # Load General Remediation Guides
            guides_path = self.knowledge_dir / "remediation_guides.json"
            if guides_path.exists():
                self.kb["remediation_guides"] = json.loads(guides_path.read_text(encoding="utf-8"))
                
            logger.info("Security knowledge base loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")

    def _load_external_datasets(self):
        """Load external dataset files from dataset folder if available."""
        import zipfile
        import csv
        import io
        
        dataset_dir = self.knowledge_dir.parent.parent.parent / "dataset"
        if not dataset_dir.exists():
            return
            
        # 1. Load MASVS from OWASP_MASVS.cdx.json
        masvs_path = dataset_dir / "OWASP_MASVS.cdx.json"
        if masvs_path.exists():
            try:
                with open(masvs_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    reqs = data.get("definitions", {}).get("standards", [])[0].get("requirements", [])
                    for req in reqs:
                        ident = req.get("identifier")
                        if ident:
                            self.kb["masvs"][ident] = {
                                "title": req.get("title", ""),
                                "text": req.get("text", ""),
                                "parent": req.get("parent", "")
                            }
                logger.info(f"Loaded {len(self.kb['masvs'])} MASVS controls from dataset")
            except Exception as e:
                logger.error(f"Error loading MASVS cdx json: {e}")
                
        # 2. Load CAPEC from any *.csv.zip files in dataset folder
        for capec_zip in dataset_dir.glob("*.csv.zip"):
            try:
                with zipfile.ZipFile(capec_zip, 'r') as z:
                    for name in z.namelist():
                        if name.endswith('.csv'):
                            with z.open(name) as f:
                                text_stream = io.TextIOWrapper(f, encoding='utf-8-sig', errors='ignore')
                                reader = csv.DictReader(text_stream)
                                for row in reader:
                                    clean_row = {k.strip("'\"") if k else "": v for k, v in row.items()}
                                    capec_id = clean_row.get("ID")
                                    if capec_id:
                                        self.kb["capec"][f"CAPEC-{capec_id}"] = {
                                            "name": clean_row.get("Name", ""),
                                            "description": clean_row.get("Description", ""),
                                            "mitigations": clean_row.get("Mitigations", ""),
                                            "related_weaknesses": clean_row.get("Related Weaknesses", "")
                                        }
                logger.info(f"Loaded CAPEC references from {capec_zip.name}")
            except Exception as e:
                logger.error(f"Error loading CAPEC zip {capec_zip.name}: {e}")

        # 3. Load NVD CVEs from recent or modified json zips to save memory
        cve_zips = list(dataset_dir.glob("nvdcve-2.0-recent.json.zip")) + list(dataset_dir.glob("nvdcve-2.0-modified.json.zip"))
        for cve_zip in cve_zips:
            try:
                with zipfile.ZipFile(cve_zip, 'r') as z:
                    for name in z.namelist():
                        if name.endswith('.json'):
                            with z.open(name) as f:
                                data = json.load(f)
                                vulns = data.get("vulnerabilities", [])
                                count = 0
                                for item in vulns:
                                    cve_item = item.get("cve", {})
                                    cve_id = cve_item.get("id")
                                    descriptions = cve_item.get("descriptions", [])
                                    desc_text = ""
                                    for desc in descriptions:
                                        if desc.get("lang") == "en":
                                            desc_text = desc.get("value", "")
                                            break
                                    if cve_id and desc_text:
                                        # Filter for mobile relevant CVEs to optimize RAG space
                                        desc_lower = desc_text.lower()
                                        if any(k in desc_lower for k in ["android", "ios", "apk", "ipa", "mobile"]):
                                            self.kb["cve"][cve_id] = {
                                                "description": desc_text,
                                                "references": [ref.get("url", "") for ref in cve_item.get("references", [])]
                                            }
                                            count += 1
                logger.info(f"Loaded {count} mobile-relevant CVEs from {cve_zip.name}")
            except Exception as e:
                logger.error(f"Error loading CVE zip {cve_zip.name}: {e}")

        # 4. Load full CWE catalog from cwec_latest.xml.zip
        cwec_zip = dataset_dir / "cwec_latest.xml.zip"
        if cwec_zip.exists():
            try:
                import xml.etree.ElementTree as ET
                with zipfile.ZipFile(cwec_zip, 'r') as z:
                    xml_name = z.namelist()[0]
                    with z.open(xml_name) as f:
                        context = ET.iterparse(f, events=("start", "end"))
                        context = iter(context)
                        _, root = next(context)
                        count = 0
                        for event, elem in context:
                            if event == "end":
                                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                                if tag == "Weakness":
                                    cwe_id = elem.get("ID")
                                    cwe_name = elem.get("Name")
                                    if cwe_id and cwe_name:
                                        desc_elem = elem.find(".//{http://cwe.mitre.org/cwe-7}Description")
                                        desc = desc_elem.text if desc_elem is not None else ""
                                        
                                        # Extract mitigations
                                        mitigations = []
                                        mit_group = elem.find(".//{http://cwe.mitre.org/cwe-7}Mitigations")
                                        if mit_group is not None:
                                            for mit in mit_group.findall(".//{http://cwe.mitre.org/cwe-7}Mitigation"):
                                                desc_nodes = mit.findall(".//{http://cwe.mitre.org/cwe-7}Description")
                                                desc_texts = ["".join(dn.itertext()).strip() for dn in desc_nodes]
                                                desc_texts = [dt for dt in desc_texts if dt]
                                                if desc_texts:
                                                    mitigations.append(" ".join(desc_texts))
                                                    
                                        self.kb["cwe_catalog"][f"CWE-{cwe_id}"] = {
                                            "name": cwe_name,
                                            "description": desc,
                                            "mitigations": "\n".join(mitigations) if mitigations else "Follow secure programming practices to prevent this weakness."
                                        }
                                        count += 1
                                    elem.clear()
                                    root.clear()
                logger.info(f"Loaded {count} CWE catalog entries from XML dataset")
            except Exception as e:
                logger.error(f"Error loading CWE XML catalog: {e}")

    def _build_vector_index(self):
        """
        Build the multi-strategy retrieval index:
        1. Parse all knowledge records into a shared document corpus
        2. Build TF-IDF index with bigram support
        3. Build BM25 index for Okapi BM25 ranking
        4. Initialize the HybridRetriever with RRF fusion
        5. Populate the SecurityKnowledgeGraph with CWEâ†’CAPEC edges
        """
        documents = []
        metadata = []
        
        # Index OWASP Mobile items
        for owasp_id, data in self.kb["owasp_mobile"].items():
            doc_text = f"OWASP Mobile {owasp_id} {data.get('name', '')} {data.get('description', '')} {data.get('remediation', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "owasp_mobile",
                "id": owasp_id,
                "name": data.get("name", ""),
                "remediation": data.get("remediation", "")
            })
            
        # Index OWASP API items
        for api_id, data in self.kb["owasp_api"].items():
            doc_text = f"OWASP API {api_id} {data.get('name', '')} {data.get('description', '')} {data.get('remediation', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "owasp_api",
                "id": api_id,
                "name": data.get("name", ""),
                "remediation": data.get("remediation", "")
            })
            
        # Index CWE items
        for cwe_id, data in self.kb["cwe"].items():
            doc_text = f"CWE {cwe_id} {data.get('name', '')} {data.get('remediation', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "cwe",
                "id": cwe_id,
                "name": data.get("name", ""),
                "remediation": data.get("remediation", "")
            })
            
        # Index general remediation guides
        for guide_id, guide_text in self.kb["remediation_guides"].items():
            doc_text = f"remediation guide {guide_id} {guide_text}"
            documents.append(doc_text)
            metadata.append({
                "type": "remediation_guide",
                "id": f"remediation_{guide_id}",
                "name": guide_id,
                "remediation": guide_text
            })

        # Index MASVS items
        for masvs_id, data in self.kb.get("masvs", {}).items():
            doc_text = f"MASVS {masvs_id} {data.get('title', '')} {data.get('text', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "masvs",
                "id": masvs_id,
                "name": data.get("title", ""),
                "remediation": f"Verify compliance against OWASP MASVS control {masvs_id}: {data.get('text', '')}"
            })
            
        # Index CAPEC items and populate knowledge graph
        for capec_id, data in self.kb.get("capec", {}).items():
            doc_text = f"CAPEC {capec_id} {data.get('name', '')} {data.get('description', '')} {data.get('mitigations', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "capec",
                "id": capec_id,
                "name": data.get("name", ""),
                "remediation": data.get("mitigations", "Review CAPEC attack pattern mitigations.")
            })
            # Extract CWE references from CAPEC description for knowledge graph
            rw = data.get("related_weaknesses", "")
            related_cwes = [f"CWE-{cwe}" for cwe in re.findall(r'\d+', rw)]
            if related_cwes:
                self.knowledge_graph.add_capec_mapping(capec_id, related_cwes)
            
        # Index CVE items
        for cve_id, data in self.kb.get("cve", {}).items():
            doc_text = f"CVE {cve_id} {data.get('description', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "cve",
                "id": cve_id,
                "name": cve_id,
                "remediation": f"Remediate according to CVE references: {', '.join(data.get('references', []))}"
            })

        # Index CWE Catalog items
        for cwe_id, data in self.kb.get("cwe_catalog", {}).items():
            # Skip if already indexed in custom CWE database to avoid duplication
            if cwe_id in self.kb.get("cwe", {}):
                continue
            doc_text = f"CWE {cwe_id} {data.get('name', '')} {data.get('description', '')} {data.get('mitigations', '')}"
            documents.append(doc_text)
            metadata.append({
                "type": "cwe_catalog",
                "id": cwe_id,
                "name": data.get("name", ""),
                "remediation": data.get("mitigations", "Follow secure coding standards.")
            })

        # Index arbitrary custom markdown files if any are present
        for path in self.knowledge_dir.glob("*.md"):
            try:
                content = path.read_text(encoding="utf-8")
                # Simple markdown chunking by header or paragraph
                chunks = re.split(r'\n(?=#{1,4}\s)', content)
                for j, chunk in enumerate(chunks):
                    chunk = chunk.strip()
                    if chunk:
                        documents.append(chunk)
                        metadata.append({
                            "type": "markdown",
                            "id": f"{path.name}#chunk-{j}",
                            "name": path.stem,
                            "remediation": chunk
                        })
            except Exception as e:
                logger.error(f"Error indexing markdown file {path.name}: {e}")

        # --- Build indexes ---
        # Store shared document corpus
        self._documents = documents
        self._metadata = metadata

        # 1. Build TF-IDF index (with bigram support)
        self.vector_store.fit_transform(documents, metadata)
        logger.info(f"[RAG v3.0] TF-IDF index built: {len(documents)} documents, {len(self.vector_store.vocab)} vocab tokens")

        # 2. Build BM25 index
        self.bm25_store.fit(documents)
        logger.info(f"[RAG v3.0] BM25 index built: {self.bm25_store.doc_count} documents, avg_dl={self.bm25_store.avg_dl:.1f}")

        # 3. Initialize the Hybrid Retriever with RRF fusion
        self.hybrid_retriever = HybridRetriever(
            tfidf=self.vector_store,
            bm25=self.bm25_store,
            documents=documents,
            metadata=metadata,
            rrf_k=60
        )
        logger.info(f"[RAG v3.0] HybridRetriever (RRF k=60) initialized")

        # 4. Log knowledge graph statistics
        logger.info(f"[RAG v3.0] Knowledge graph: {self.knowledge_graph.edge_count} taxonomy edges")
        logger.info(f"[RAG v3.0] Advanced RAG pipeline fully initialized [OK]")

    # ---
    # ADVANCED QUERY PIPELINE
    # ---

    def query_vector(self, query_text: str, top_n: int = 3) -> list:
        """
        Advanced multi-stage retrieval pipeline:
          Stage 1: Query Expansion (synonym augmentation)
          Stage 2: Hybrid Retrieval (BM25 + TF-IDF via RRF)
          Stage 3: Knowledge Graph Augmentation (pull related taxonomy nodes)
          Stage 4: Cross-Encoder Re-ranking (multi-signal scoring)
          Stage 5: Contextual Compression (extract relevant sentences)
        Returns a list of formatted result dictionaries.
        """
        if not query_text.strip():
            return []

        # --- Stage 1: Query Expansion ---
        expanded_query = self.query_expander.expand(query_text)

        # --- Stage 2: Hybrid Retrieval ---
        if self.hybrid_retriever:
            candidates = self.hybrid_retriever.search(expanded_query, top_n=15)
        else:
            # Fallback to basic TF-IDF if hybrid not initialized
            candidates = self.vector_store.search_formatted(expanded_query, top_n=15)

        if not candidates:
            return []

        # --- Stage 3: Knowledge Graph Augmentation ---
        # Collect IDs from top candidates and pull related taxonomy nodes
        seen_ids = {c["metadata"]["id"] for c in candidates}
        graph_additions = []

        for cand in candidates[:5]:  # Traverse graph for top-5 results
            doc_id = cand["metadata"]["id"]
            related_ids = self.knowledge_graph.get_related_ids(doc_id, depth=1)
            for rid in related_ids:
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)
                # Find the related document in our corpus
                for idx, m in enumerate(self._metadata):
                    if m["id"] == rid:
                        graph_additions.append({
                            "metadata": m,
                            "content": self._documents[idx],
                            "score": 0.005  # Low base score for graph-augmented results
                        })
                        break

        candidates.extend(graph_additions)

        # --- Stage 4: Cross-Encoder Re-ranking ---
        reranked = self.reranker.rerank(query_text, candidates, top_n=top_n)

        # --- Stage 5: Format and Compress ---
        formatted = []
        for r in reranked:
            compressed_content = self.compressor.compress(
                query_text, r["content"], max_sentences=3
            )
            formatted.append({
                "id": r["metadata"]["id"],
                "type": r["metadata"]["type"],
                "name": r["metadata"]["name"],
                "remediation": r["metadata"]["remediation"],
                "content": compressed_content,
                "score": r.get("rerank_score", r.get("score", 0.0))
            })

        return formatted

    def query(self, topic: str) -> dict:
        """
        Query the knowledge base for a topic.
        Uses advanced hybrid pipeline while maintaining backward compatibility.
        """
        topic_lower = topic.lower()
        results = {}

        # 1. Classical Exact Keyword Search (Backward Compatibility)
        for mid, data in self.kb["owasp_mobile"].items():
            if topic_lower in data["name"].lower() or topic_lower in data["description"].lower():
                results[mid] = data

        for key, guide in self.kb["remediation_guides"].items():
            if topic_lower in key or topic_lower in guide.lower():
                results[f"remediation_{key}"] = guide

        for cwe_id, data in self.kb["cwe"].items():
            if topic_lower in cwe_id.lower() or topic_lower in data["name"].lower():
                results[cwe_id] = data

        # 2. Advanced Hybrid Vector Similarity Search
        vector_matches = self.query_vector(topic, top_n=5)
        if vector_matches:
            results["similarity_matches"] = vector_matches

        return results

    def get_remediation(self, owasp_id: str) -> str:
        """Get remediation guide for an OWASP category."""
        if owasp_id in self.kb["owasp_mobile"]:
            return self.kb["owasp_mobile"][owasp_id].get("remediation", "No remediation available.")
        return "No remediation guide found."

    def enrich_finding(self, finding: dict) -> dict:
        """
        Enrich a finding with knowledge base information using multi-source
        advanced RAG retrieval. Attaches up to 3 RAG contexts from different
        knowledge source types for comprehensive coverage.
        """
        enriched = {**finding}
        
        # --- Traditional Exact-Match Enrichment ---
        # OWASP Mobile enrichment
        owasp = finding.get("owasp", "")
        if owasp in self.kb["owasp_mobile"]:
            enriched["owasp_details"] = self.kb["owasp_mobile"][owasp]
            enriched["remediation"] = self.kb["owasp_mobile"][owasp]["remediation"]
            
        # CWE enrichment
        cwe = finding.get("cwe", "")
        if cwe in self.kb["cwe"]:
            enriched["remediation"] = self.kb["cwe"][cwe]["remediation"]

        # CWE Catalog enrichment (fallback for CWEs not in custom database)
        if not enriched.get("remediation") and cwe in self.kb.get("cwe_catalog", {}):
            enriched["remediation"] = self.kb["cwe_catalog"][cwe].get(
                "mitigations", "Follow secure programming practices."
            )

        # --- Advanced Multi-Source RAG Enrichment ---
        query_text = f"{finding.get('title', '')} {finding.get('description', '')}"
        if query_text.strip():
            # Retrieve top-5 matches via the full advanced pipeline
            vector_matches = self.query_vector(query_text, top_n=5)

            if vector_matches:
                # De-duplicate by source type: pick the best from each type
                seen_types = set()
                diverse_contexts = []

                for match in vector_matches:
                    match_type = match["type"]
                    if match_type not in seen_types and len(diverse_contexts) < 3:
                        seen_types.add(match_type)
                        diverse_contexts.append({
                            "doc_id": match["id"],
                            "type": match["type"],
                            "name": match["name"],
                            "score": match["score"],
                            "compressed_context": match["content"]
                        })

                # Attach multi-source RAG context array
                enriched["rag_context"] = diverse_contexts

                # Primary context (backward compatible single-context field)
                best_match = vector_matches[0]
                enriched["rag_primary"] = {
                    "doc_id": best_match["id"],
                    "type": best_match["type"],
                    "score": best_match["score"]
                }

                # Save the static template remediation as backup
                template_rem = enriched.get("remediation") or best_match["remediation"]
                enriched["template_remediation"] = template_rem

                # --- Generative RAG Step (True LLM Verification & Generation) ---
                severity = finding.get("severity", "info").lower()
                generated_remediation = None
                
                # Check if this is a code-level finding (from decompiled files, raw evidence with paths, or zero-day analyzer)
                evidence_text = str(finding.get("evidence", "")).lower()
                target_file = (finding.get("file_path") or finding.get("file") or "").lower()
                is_code_flow = (
                    target_file.endswith((".java", ".kt", ".swift", ".m", ".xml", ".plist", ".so", ".dex", ".smali")) or
                    any(ext in evidence_text for ext in [".java", ".kt", ".swift", ".m", ".xml", ".plist", ".dex", ".so", "found in", "classes"]) or
                    "zero-day" in finding.get("title", "").lower() or
                    "cryptography" in finding.get("title", "").lower() or
                    "key" in finding.get("title", "").lower() or
                    "secret" in finding.get("title", "").lower()
                )
                is_third_party = finding.get("confidence") == "low"
                
                # Verify critical, high, and medium severity code findings within scan budget
                if severity in ("critical", "high", "medium") and is_code_flow and not is_third_party and finding.get("llm_audit_eligible", True):
                    # Build compact context block from retrieved sources (compressed to maximize inference speed)
                    context_block = ""
                    for idx, ctx in enumerate(diverse_contexts):
                        context_block += f"[Source {idx+1}: {ctx['doc_id']} ({ctx['type']})]\n"
                        context_block += f"{str(ctx.get('compressed_context', ''))[:250].strip()}...\n\n"

                    system_prompt = (
                        "You are an expert mobile application security auditor and secure coding engineer.\n"
                        "Your task is to analyze the detected vulnerability in the mobile application code and determine if it is a genuine vulnerability (True Positive) or a false prediction / false positive (False Positive) due to dummy data, mock variables, test environments, third-party library internals, or harmless context.\n\n"
                        "Keep your response concise. You MUST format your response with the following exact labels, each starting on a new line:\n"
                        "ANALYSIS: [1-2 concise sentences explaining whether this is a genuine vulnerability or false positive based on context]\n"
                        "VERDICT: [VULNERABLE or FALSE_POSITIVE]\n"
                        "CONFIDENCE: [0-100]%\n"
                        "REMEDIATION: [1-2 sentences concrete code fix or N/A]"
                    )

                    app_name = finding.get("app_name") or finding.get("package_name") or ""
                    file_path = finding.get("file_path") or finding.get("file") or ""
                    code_snippet = finding.get("code_snippet") or ""

                    loc_str = ""
                    if app_name:
                        loc_str += f"Target Application: {app_name}\n"
                    if file_path:
                        loc_str += f"Target File: {file_path}\n"
                    snippet_str = f"Code Snippet:\n{str(code_snippet)[:1000]}\n" if code_snippet else ""

                    user_prompt = (
                        f"{loc_str}"
                        f"Vulnerability Title: {str(finding.get('title', ''))[:200]}\n"
                        f"Category/CWE: {finding.get('category')} / {finding.get('cwe')}\n"
                        f"Severity: {finding.get('severity')}\n"
                        f"Description: {str(finding.get('description', ''))[:500]}\n"
                        f"{snippet_str}"
                        f"Evidence Code: {str(finding.get('evidence', ''))[-1000:]}\n\n"
                        f"--- RETRIEVED SECURITY REFERENCE CONTEXT ---\n"
                        f"{context_block}\n"
                        f"--- INSTRUCTIONS ---\n"
                        f"Perform the audit and return the formatted response containing ANALYSIS, VERDICT, CONFIDENCE, and REMEDIATION."
                    )

                    # Query the generative LLM with isolated app context key
                    context_key = f"{app_name}:{file_path}:{finding.get('cwe', '')}"
                    generated_remediation = self.llm_client.generate_completion(system_prompt, user_prompt, context_key=context_key)
                
                if generated_remediation:
                    import re
                    # Parse structured LLM Verdict
                    verdict_match = re.search(r'VERDICT:\s*(VULNERABLE|FALSE_POSITIVE)', generated_remediation, re.IGNORECASE)
                    confidence_match = re.search(r'CONFIDENCE:\s*(\d+)%', generated_remediation)
                    analysis_match = re.search(r'ANALYSIS:\s*(.*?)(?=\nVERDICT:|\nCONFIDENCE:|\nREMEDIATION:|\Z)', generated_remediation, re.DOTALL | re.IGNORECASE)
                    if not analysis_match:
                        analysis_match = re.search(r'ANALYSIS:\s*(.*?)(?=\nREMEDIATION:|\Z)', generated_remediation, re.DOTALL | re.IGNORECASE)
                    remediation_match = re.search(r'REMEDIATION:\s*(.*)', generated_remediation, re.DOTALL | re.IGNORECASE)

                    verdict_val = verdict_match.group(1).upper() if verdict_match else ""
                    confidence_val = int(confidence_match.group(1)) if confidence_match else 90
                    analysis_val = analysis_match.group(1).strip() if analysis_match else ""
                    remediation_val = remediation_match.group(1).strip() if remediation_match else ""

                    analysis_lower = analysis_val.lower()
                    remediation_upper = remediation_val.upper()

                    # Semantic indicators that LLM judged this as a false positive
                    # Important: check for negation patterns FIRST to avoid inverting genuine findings
                    negation_prefixes = [
                        "not a false positive", "is not a false positive",
                        "not a false prediction", "is not harmless",
                        "not harmless", "is a genuine vulnerability",
                        "is a real vulnerability", "is a valid vulnerability",
                        "this is a true positive", "this is not a mock",
                    ]
                    has_negated_fp = any(p in analysis_lower for p in negation_prefixes)

                    fp_indicators = [
                        "false positive", "false prediction", "not a vulnerability", 
                        "not a genuine vulnerability", "harmless", "mock", "dummy data",
                        "test environment", "no security risk", "does not pose a security risk",
                        "concludes that this is a false positive", "premature and likely incorrect",
                        "not a valid vulnerability", "is a false positive"
                    ]
                    has_fp_semantics = any(p in analysis_lower for p in fp_indicators) and not has_negated_fp
                    is_na_remediation = remediation_upper in ("N/A", "NONE", "NOT APPLICABLE", "N/A.", "NO REMEDIATION REQUIRED", "NO REMEDIATION")

                    is_fp = False
                    if verdict_val == "FALSE_POSITIVE":
                        is_fp = True
                    elif has_fp_semantics and (is_na_remediation or "is a false positive" in analysis_lower):
                        is_fp = True
                    elif confidence_val < 30 and has_fp_semantics:
                        is_fp = True

                    # Save cognitive metadata
                    enriched["generative_rag_active"] = True
                    enriched["cognitive_confidence"] = f"{confidence_val}%"
                    enriched["cognitive_analysis"] = analysis_val

                    if is_fp:
                        enriched["is_false_positive"] = True
                        enriched["remediation"] = f"LLM Auditor classified this finding as a FALSE POSITIVE (Confidence: {confidence_val}%).\nReason: {analysis_val}"
                    else:
                        enriched["is_false_positive"] = False
                        # If remediation is N/A or empty, fallback to clean text analysis
                        if not remediation_val or is_na_remediation:
                            enriched["remediation"] = f"Vulnerability Verified by LLM Auditor (Confidence: {confidence_val}%).\n\nAnalysis: {analysis_val}\n\nRemediation Strategy: {template_rem}"
                        else:
                            enriched["remediation"] = f"Vulnerability Verified by LLM Auditor (Confidence: {confidence_val}%).\n\nAnalysis: {analysis_val}\n\nRecommended Action:\n{remediation_val}"
                else:
                    # Fallback to standard static template if LLM is disabled, offline, or skipped
                    enriched["remediation"] = template_rem
                    enriched["generative_rag_active"] = False
                    enriched["is_false_positive"] = False
                    # Only mark as timeout fallback if LLM was available but the finding was eligible and still didn't get audited
                    if self.llm_client.provider != "none" and severity in ("critical", "high", "medium") and finding.get("llm_audit_eligible", False):
                        enriched["llm_timeout_fallback"] = True
                    else:
                        enriched["llm_timeout_fallback"] = False



        # --- Knowledge Graph Cross-References ---
        if cwe:
            related = self.knowledge_graph.get_related_ids(cwe, depth=1)
            if related:
                enriched["related_taxonomy"] = list(related)[:5]
        return enriched


