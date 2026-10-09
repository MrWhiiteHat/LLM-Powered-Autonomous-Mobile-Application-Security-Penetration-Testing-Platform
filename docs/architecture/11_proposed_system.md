# Chapter 11: Proposed System

The proposed system, **Mobile Security Agent (MSA) v2.0**, introduces a single-process hybrid architecture:
*   **Process-Local Core:** Runs as a lightweight FastAPI server without requiring external databases.
*   **Offline RAG Engine:** Embedding pipelines ingest OWASP guides and CWE metadata locally using Sentence Transformers and ChromaDB.
*   **Cognitive LLM Auditor:** A local LLM (Qwen-3.5 4B) executes a structured verification loop to analyze code contexts and suppress false alerts.
*   **Asynchronous Orchestration:** Thread pools run static scanners, ADB dynamic hooks, and Frida engines concurrently.
