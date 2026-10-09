# Chapter 21: Low-Level Architecture

The Low-Level Architecture (LLA) defines the code components, helper modules, and library configurations:
*   `main.py` binds the FastAPI server routes.
*   `ast_analyzer.py` handles recursive class parsing.
*   `frida_engine.py` handles daemon thread spawning and ADB controls.
*   `rag_engine.py` handles Sentence Transformer tokenization and vector querying.
*   `llm_client.py` handles HTTP calls to the local Ollama instance.
