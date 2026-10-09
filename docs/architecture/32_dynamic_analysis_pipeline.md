# Chapter 32: Dynamic Analysis Pipeline

1. **ADB Handshake:** Verifies connectivity to the active emulator.
2. **Instrumentation Injection:** Frida attaches to the target process.
3. **Hooking Script Execution:** Overrides class methods for filesystem, network, and cryptographic APIs.
4. **Capture:** Memory buffers and intercept logs are recorded before package termination.
