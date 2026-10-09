# Chapter 34: RAG Pipeline

1. **Ingestion:** Security guidelines (CWE, OWASP) are parsed and chunked.
2. **Vectorization:** Generates embeddings using `all-MiniLM-L6-v2`.
3. **Indexing:** Embeddings are written to ChromaDB.
4. **Retrieval:** The scanner queries ChromaDB using decompiler finding titles to retrieve context for the LLM Auditor.
