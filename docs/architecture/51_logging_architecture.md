# Chapter 51: Logging Architecture

System logs are structured and recorded:
*   **File Logging:** Core service operations write to `logs/agent.log`.
*   **Scan-Specific Logging:** Decompiler and instrumentation logs are saved as dedicated `.log` files in the scan directory.
*   **Console Logging:** Critical status changes are output in real time to standard output.
