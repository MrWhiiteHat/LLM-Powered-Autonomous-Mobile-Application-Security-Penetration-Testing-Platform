# MSA v2.0 Architecture Audit & Benchmark Integration Document

**Document Version:** 1.0.0  
**Project:** LLM-Based Autonomous Mobile Application Security Penetration Testing Agent (MSA v2.0)  
**Target Environment:** Python 3.14.0, FastAPI 0.109.0, Uvicorn 0.27.0, Windows 11 Pro  
**Hardware Profile:** Intel Core i7-12700H (14 cores, 20 threads), 16 GB DDR5 RAM  

---

## 1. System Overview & Core Capabilities

The Mobile Security Agent (MSA v2.0) is an autonomous, offline-first mobile application penetration testing framework. It audits Android (APK, XAPK) and iOS (IPA) packages across a sequential 10-phase pipeline, integrating static analysis, AST taint flow analysis, reverse engineering, dynamic instrumentation (Frida), a local 8-component RAG (Retrieval-Augmented Generation) knowledge engine, an LLM Cognitive Auditor, and automated CVSS v3.1 risk assessment.

```
                          ┌─────────────────────────────────────┐
                          │         PRESENTATION LAYER          │
                          │ Web Dashboard | Real-time Logs | UI │
                          └──────────────────┬──────────────────┘
                                             │ HTTP REST / Upload
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                APPLICATION LAYER                                       │
│ FastAPI Async Orchestrator (Port 8001) | Non-blocking Background Tasks                 │
│                                                                                        │
│  Phase 1: Reconnaissance (file_handler.py, hashlib, androguard)                        │
│  Phase 1.5: Decompilation (JADX decompilation -> Androguard -> ZIP fallback)           │
│  Phase 2: Static Analysis (static_analysis.py - Manifest, permissions, secrets)       │
│  Phase 2.5: AST Taint Flow (Java AST parser, 12 sources -> 13 dangerous sinks)        │
│  Phase 3: Reverse Engineering (reverse_engineering.py - Endpoints, configs, obfuscation)│
│  Phase 4: Storage Security (storage_analysis.py - SharedPref, SQLite, Keystore)       │
│  Phase 5: Network Security (network_analysis.py - TLS/SSL, cleartext, cert pinning)   │
│  Phase 6: API Security (api_testing.py - OWASP API Top 10, JWT, GraphQL, BOLA)        │
│  Phase 7: Heuristic & Zero-Day (zero_day_analyzer.py - Reflection, DCL, custom crypto)│
│  Phase 8: Dynamic Runtime (dynamic_analysis.py - Frida 7 hooks, ADB automation)       │
│  Phase 9: RAG Vulnerability Mapping (vulnerability_mapper.py + rag_engine.py)          │
│  Phase 10: Risk Assessment & Reporting (risk_assessment.py, report_generator.py)      │
└────────────────────────────────────┬───────────────────────────────────────────────────┘
                                     │ Semantic Context & Knowledge
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                INTELLIGENCE LAYER                                      │
│  RAG Engine v3.0: 2,075 indexed documents, 62,710 vocabulary tokens                   │
│  8-Component Hybrid Retrieval:                                                         │
│    1. Query Expander (25 categories)       2. BM25 Probabilistic (k1=1.5, b=0.75)      │
│    3. TF-IDF Vector Space                  4. Reciprocal Rank Fusion (RRF k=60)        │
│    5. Authority Weight Boost               6. Knowledge Graph (34 taxonomy edges)      │
│    7. Cross-Encoder Re-ranker              8. Contextual Compression                   │
│  Local LLM Auditor: Ollama (Qwen 2.5-Coder 1.5B, CPU execution, num_gpu=0)             │
│  Knowledge Bases: OWASP Mobile M1-M10, OWASP API Top 10, MASVS v2.1.0, CWE, CAPEC, NVD│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Inventory & Audit Findings

| Module | Location | Primary Responsibilities | Analysis Technique | Ground Truth Evaluation Capability |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `backend/utils/file_handler.py` | Package validation, MD5/SHA-1/SHA-256 hashes, SDK levels, architecture detection. | Metadata extraction | Hash & package verification |
| **Decompilation** | `backend/modules/static_analysis.py` | JADX wrapper with Androguard and ZIP decompressor fallbacks. | Bytecode disassembly | Java AST extraction |
| **Static Analysis** | `backend/modules/static_analysis.py` | Manifest permissions, exported components, Shannon entropy secret scanning, pattern matching. | Regex, AST parsing | Permissions, exported activities, secrets |
| **AST Taint Flow** | `backend/modules/static_analysis.py` | Inter-procedural taint propagation from 12 sensitive sources to 13 dangerous sinks. | Data-flow AST analysis | DroidBench taint validation |
| **Reverse Eng.** | `backend/modules/reverse_engineering.py` | URL/IP extraction, Firebase configurations, obfuscation scoring, anti-tamper detection. | String & smali scanning | Hardcoded URL / Firebase leaks |
| **Storage Security**| `backend/modules/storage_analysis.py` | World-readable files, unencrypted SQLite (SQLCipher audit), SharedPreferences leaks. | File I/O & regex analysis | Insecure storage (CWE-312, CWE-922) |
| **Network Security**| `backend/modules/network_analysis.py` | Cleartext traffic flags, TLS 1.2+ validation, trust managers, OkHttp cert pinning. | XML & bytecode scanning | Network security (CWE-319, CWE-295) |
| **API Testing** | `backend/modules/api_testing.py` | OWASP API Top 10 patterns, JWT verification, GraphQL endpoints, BOLA/IDOR detection. | Endpoint heuristics | API flaws (API1 - API10) |
| **Heuristics** | `backend/modules/zero_day_analyzer.py` | Reflection (`Class.forName`), dynamic class loading (`DexClassLoader`), XOR cryptography. | Heuristic pattern analysis| Anomaly & suspicious pattern metrics |
| **Dynamic Engine** | `backend/modules/dynamic_analysis.py` | Automated ADB connection, Frida server lifecycle, 7 instrumentation hooks. | Dynamic runtime hooking | Runtime verification (SQL, crypto, SSL) |
| **RAG Engine** | `backend/knowledge/rag_engine.py` | Hybrid BM25 + TF-IDF retrieval fused with RRF (k=60), 2,075 docs, knowledge graph. | In-memory Information Retrieval | Top-K relevance & RAG ablation |
| **LLM Client** | `backend/knowledge/llm_client.py` | Offline HTTP client for Ollama `qwen2.5-coder:1.5b` with circuit breaker and disk cache. | Generative AI reasoning | False-positive audit & patch gen |
| **Vulnerability Mapper**| `backend/modules/vulnerability_mapper.py`| Merges raw findings, enriches with RAG knowledge, triggers LLM Cognitive Auditor. | Cognitive auditing | Noise suppression evaluation |
| **Risk Assessor** | `backend/modules/risk_assessment.py` | CVSS v3.1 scoring calculation, severity ranking, OWASP/CWE taxonomy categorization. | Algorithmic scoring | CVSS accuracy & consistency |
| **Report Generator**| `backend/modules/report_generator.py` | Standalone HTML (Jinja2) and structured JSON generation. | Report serialization | Verification of generated remediation |

---

## 3. Integration Points for Benchmark Framework

To evaluate MSA v2.0 without contaminating production code, the **Benchmark Framework** interfaces with MSA at the following integration layers:

1. **Direct Module Invocation (Headless Runner):**
   * Bypasses the FastAPI web layer and runs tests programmatically through `backend/modules/` orchestrator.
   * Enables fine-grained ablation studies (e.g., disabling RAG, disabling LLM, running static-only vs static+dynamic).
2. **REST API Interface (Black-box Runner):**
   * Submits APKs to `POST /api/scan`, polls `GET /api/scan/{id}`, and evaluates output via `GET /api/scan/{id}/report/json`.
   * Verifies end-to-end user-facing pipeline performance.
3. **Ground Truth Validation Engine:**
   * Ingests canonical ground truth per benchmark (e.g., DroidBench ground-truth manifests, Ghera bug descriptions).
   * Normalizes scanner findings to standard taxonomy tuples: `(Package, Vulnerability Type, CWE-ID, File/Line, Confidence)`.
   * Evaluates classification performance: True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN).
4. **Relational Benchmark Database (`benchmark_results.db`):**
   * Persists every execution run with exact environment timestamps, software versions, raw detector outputs, and normalized metrics.
5. **IEEE Publication Reporting Engine:**
   * Exports automated IEEE-formatted markdown/LaTeX tables, statistical confidence intervals, and visualization artifacts.

---

## 4. Ethical & Legal Guardrails

Every target processed by the benchmark framework must have an explicit governance declaration:
* `BENCHMARK`: Intentionally synthetic test cases (DroidBench, Ghera, OWApp, IccBench).
* `AUTHORIZED`: Intentionally vulnerable test applications (DIVA, AndroGoat, InsecureBankv2, OVAA).
* `RESEARCH_DATASET`: Legally acquired research corpora (AndroZoo, authorized offline real-world apps).
* Dynamic analysis is strictly restricted to local emulators/test hardware. No external network requests or unauthorized API attacks are permitted.
