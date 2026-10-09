# Chapter 20: High-Level Architecture

The High-Level Architecture (HLA) organizes the platform into logical domains:
1. **Recon & Extraction Domain:** Handles package validation, unzipping, and manifest parses.
2. **Analysis Domain:** Houses the static AST matcher, taint tracker, and Frida dynamics hooker.
3. **Cognitive Domain:** Houses the ChromaDB vector database and LLM completion pipelines.
4. **Presentation Domain:** Houses the HTML reporting engine.

All domains run on the local host machine, communicating via process-local loopback APIs.
