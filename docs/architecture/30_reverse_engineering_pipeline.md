# Chapter 30: Reverse Engineering Pipeline

```mermaid
graph TD
    APK[" Android APK"] -->|Unzip| DEX[" classes.dex"]
    DEX -->|JADX Decompile| Java["☕ Java Classes"]
    APK -->|Apktool Disassemble| Smali[" Smali Bytecode"]
    APK -->|Extract Native| SO["⚙️ lib/*.so (JNI)"]
```
