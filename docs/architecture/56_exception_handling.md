# Chapter 56: Exception Handling

Specific Python exceptions are mapped:
*   `RuntimeError` / `subprocess.TimeoutExpired`: Handled in decompiler calls.
*   `frida.ProcessNotFoundError`: Handled in hooking loops.
*   `json.JSONDecodeError`: Catches malformed report configurations.
