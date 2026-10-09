# Chapter 5: Abstract

This document details the software design specification, Low-Level Architecture (LLA), High-Level Architecture (HLA), and verification methodologies of the Mobile Security Agent (MSA) v2.0. 

By utilizing static decompiler utilities alongside active Frida dynamic memory intercepts, the platform analyzes application configurations, data storage patterns, network APIs, and cryptographic flows. 

A core contribution is the implementation of an offline, process-local RAG system. This system queries semantic context from standard NVD CVE, MITRE CWE, and OWASP Mobile guides, compiling the information into a structured context window for an offline LLM auditor. 

Experimental evaluations against the DroidBench v3.0 benchmark demonstrate an F1-score of 0.938, demonstrating that the engine matches or exceeds the precision of conventional cloud-based SAST/DAST utilities while maintaining absolute offline confidentiality.
