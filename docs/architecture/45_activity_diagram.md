# Chapter 45: Activity Diagram

```mermaid
stateDiagram-v2
    [*] --> Upload
    Upload --> Decompilation
    state Decompilation {
        [*] --> JADX_Run
        JADX_Run --> AST_Scan
    }
    Decompilation --> Runtime_Hooking
    state Runtime_Hooking {
        [*] --> Install_APK
        Install_APK --> Run_Frida
    }
    Runtime_Hooking --> AI_Audit
    AI_Audit --> Report_Generation
    Report_Generation --> [*]
```
