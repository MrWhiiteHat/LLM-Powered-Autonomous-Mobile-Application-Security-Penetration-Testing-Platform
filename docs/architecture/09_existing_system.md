# Chapter 9: Existing System

Existing systems, such as Mobile Security Framework (MobSF) or proprietary enterprise SAST engines, function by running decompiler binaries (JADX, Apktool) and matching rules against the decompiled output. 
While effective at identifying standard issues, they function statically. They lack a process-local validation mechanism to verify if a finding is a mock placeholder or unreachable. Furthermore, dynamic assessments in these systems require manual test executions and separate physical setups.
