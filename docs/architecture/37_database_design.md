# Chapter 37: Database Design

The platform uses a database-less architecture:
*   **JSON Persistence:** Scan metadata, history logs, and results are stored directly as structured JSON files under `reports/` and `scan_history.json`.
*   **ChromaDB Vector Store:** Used for vector index storage, persisting embeddings as local parquet/bin files on disk.
