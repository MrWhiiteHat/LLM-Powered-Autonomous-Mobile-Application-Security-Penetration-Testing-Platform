# Chapter 25: Complete Workflow

The platform executes a unified workflow when analyzing a mobile binary:
1. **Upload:** User posts the APK/IPA file to `/api/scan`.
2. **Decompile:** JADX extracts Dalvik bytecodes to Java files.
3. **Static Audit:** AST checks locate secrets, bad TLS ciphers, and unencrypted databases.
4. **Dynamic Audits:** ADB installs the APK, launches it, hooks APIs, and captures memory dumps.
5. **Enrichment:** Validated findings are matched against local RAG security catalogs.
6. **Reporting:** Findings, evidence, and remediations are written to HTML/JSON files.
