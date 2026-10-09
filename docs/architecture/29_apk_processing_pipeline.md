# Chapter 29: APK Processing Pipeline

1. **Extraction:** The APK file is unzipped to retrieve the manifest, resource assets, and Dalvik DEX executables.
2. **Decoding:** Apktool translates binary XML files to readable layouts.
3. **Decompilation:** JADX translates DEX executables back to Java code.
4. **JNI Extraction:** Shared libraries (`.so` binaries) are extracted for assembly string parses.
