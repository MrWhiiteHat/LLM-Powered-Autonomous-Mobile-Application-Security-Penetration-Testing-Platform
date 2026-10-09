# Chapter 18: Technology Stack

The technology stack is selected to prioritize offline execution and high performance:

| Technology | Purpose | Selection Rationale |
|:---|:---|:---|
| **Python / FastAPI** | API Gateway & Orchestrator | High asynchronous execution speed, built-in OpenAPI schema support, and native ML integrations. |
| **Java JRE / JADX** | Dalvik to Java Decompiler | High-fidelity Java source recovery from DEX files. |
| **Frida / ADB** | Runtime Hooking & Control | Direct memory instrumentation and control over Android emulators. |
| **ChromaDB / LangChain** | Vector Database & RAG | Lightweight, process-local database for vector storage with zero external engine requirements. |
| **Ollama / Qwen-3.5** | Offline LLM Completions | High performance-to-size ratio, low RAM usage, and offline execution capabilities. |
