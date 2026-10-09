# Chapter 58: Plugin Architecture

MSA v2.0 implements a modular plugin architecture:
*   New security check rules are loaded dynamically from `/backend/modules/rules/`.
*   Analysis engines conform to a unified interface (`decompile()`, `analyze()`, `generate_report()`).
