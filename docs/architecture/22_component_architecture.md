# Chapter 22: Component Architecture

Each component acts as a decoupled plugin:
*   **Static Component:** Reconstructs directories, decompiles APKs, and performs regex-based string extraction.
*   **Dynamic Component:** Operates ADB connections, installs applications, runs dynamic hooks, and parses logcat files.
*   **RAG Component:** Standardizes taxonomy data into structured documents.
*   **Reports Component:** Merges static, dynamic, and AI findings into single JSON objects.
