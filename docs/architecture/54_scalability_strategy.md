# Chapter 54: Scalability Strategy

*   **Horizontal Scaling:** Multiple scanner worker nodes can run concurrently.
*   **Stateless Gateway:** The FastAPI controller operates statelessly, allowing round-robin routing of file tasks.
*   **Offline Vector Distribution:** Embedding indexes can be pre-built and packaged inside Docker containers.
