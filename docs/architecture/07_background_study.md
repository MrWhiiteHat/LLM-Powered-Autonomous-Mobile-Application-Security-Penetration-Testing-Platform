# Chapter 7: Background Study

The mobile application security landscape has shifted from basic client-side analysis to complex, runtime verification. 
Historically, Android security focused on parsing permissions in the `AndroidManifest.xml` and run-time testing. Today, security testing is divided into:
1. **Static Application Security Testing (SAST):** Scans Dalvik bytecode, Java class decompilations, or binary strings without executing the application.
2. **Dynamic Application Security Testing (DAST):** Hooking APIs and decrypting traffic during active runtime.
3. **Software Composition Analysis (SCA):** Identifying vulnerable third-party dependencies (SDKs).

MSA v2.0 bridges these paradigms by combining them into a unified, hybrid pipeline validated by local machine learning vector graphs.
