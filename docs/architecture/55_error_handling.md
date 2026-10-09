# Chapter 55: Error Handling

The platform handles analysis failures gracefully:
*   If JADX fails to parse a source file, the static parser falls back to smali disassembly.
*   If Frida encounters an attachment timeout, the dynamic scanner registers a timeout error and proceeds to compile the report.
