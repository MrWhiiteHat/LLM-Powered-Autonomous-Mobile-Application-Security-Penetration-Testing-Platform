# Chapter 49: AI Architecture

The AI architecture consists of:
1. **Embedding Generator:** Sentence Transformers (`all-MiniLM-L6-v2`) running locally to vectorize text.
2. **Vector Index:** ChromaDB storing chunked data locally.
3. **Cognitive Auditor:** A locally hosted LLM running inside Ollama.

These components coordinate to execute prompt generation, context retrieval, and verification pipelines.
