# Chapter 19: System Architecture

The MSA platform relies on a **Decoupled Asynchronous pipeline** structured into a three-layer architecture:

```mermaid
graph TD
    UI[" Presentation Layer (HTML/JS Dashboard)"] -->|Asynchronous API Calls| API["⚡ Application Gateway (FastAPI)"]
    API -->|Launch Workers| Engine["⚙️ Analysis Engine (Static & Dynamic Tasks)"]
    Engine -->|Embeddings Query| VDB[" Vector Knowledge Base (ChromaDB + LLM)"]
```

The Application Gateway coordinates incoming requests, stores binaries locally, and spawns concurrent workers for static and dynamic analysis tasks.
