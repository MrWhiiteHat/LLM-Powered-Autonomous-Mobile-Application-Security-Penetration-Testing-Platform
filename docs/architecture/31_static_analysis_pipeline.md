# Chapter 31: Static Analysis Pipeline

The static analysis pipeline runs sequential checkers:
*   **Manifest Auditor:** Verifies exported components, backup flags, and network configuration references.
*   **AST Regex Engine:** Scans Java source files for secret formats, insecure storage structures, and API keys.
*   **Proximity Filter:** Verifies context around findings to suppress decoy variables.
