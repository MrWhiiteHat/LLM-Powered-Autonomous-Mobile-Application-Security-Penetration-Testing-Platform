# Chapter 38: API Design

The platform exposes RESTful endpoints:
*   `POST /api/scan`: Uploads a binary and starts a scan.
*   `GET /api/scans`: Retrieves the historical scan log.
*   `GET /api/scan/{scan_id}`: Retrieves detailed findings for a scan.
*   `GET /api/knowledge/{topic}`: Performs a semantic search against the RAG vector index.
*   `GET /api/health`: Returns system health and model statuses.
