# Chapter 50: Security Architecture

The platform prioritizes local data security:
*   **Local Sandboxing:** Emulators run dynamic checks inside virtual sandboxes.
*   **No Cloud Egress:** All analytical calculations run locally.
*   **Path Sanitization:** File upload paths are sanitized to prevent directory traversal attacks.
