# Recall-Focused Upgrade — Mobile Security Agent

**Date:** 2026-07-08
**Goal:** Reduce false negatives (missed real vulnerabilities) and upgrade the platform, measured against a curated labeled APK set.

## Problem framing (root causes of false negatives)

| # | Root cause | Evidence | Impact |
|---|-----------|----------|--------|
| A | No real decompilation — code analysis falls back to raw ASCII string grep (`[\x20-\x7e]{8,}`, ASCII-only, len≥8) | `backend/utils/analysis_helpers.py:399` | Loses code structure; misses UTF-16 strings, crypto/WebView/SQLi call patterns |
| B | Taint engine never runs — the whole `ASTAnalyzer` is gated behind jadx being installed | `backend/main.py:267` | The exact bug class DroidBench measures is invisible |
| C | Findings silently dropped — mapper deletes low-confidence low/info findings and auto-downgrades all third-party hits | `backend/modules/vulnerability_mapper.py:83-92` | Real-but-uncertain findings vanish before the report |

Additional facts:
- jadx is **not** installed on the target machine; `androguard==3.3.5` (pure-Python DEX analysis) is already in `requirements.txt`.
- `ast_analyzer.py` parses **Java source** via `javalang`; androguard yields DEX/smali + an XREF graph, so a bridge is required.
- An Ollama `LLMClient` exists (`backend/knowledge/llm_client.py`) but is only referenced by the RAG engine — not wired into detection.
- Finding shape (dict): `title`, `severity`, `cwe`, `owasp`, `confidence`, `file`, `evidence`, plus mapper/risk enrichments.

## Core architectural decision — androguard ↔ javalang bridge

**Chosen: Option A (androguard as a source/corpus provider) + a thin slice of Option B (XREF source→sink taint).**

- androguard `AnalyzeAPK` enumerates every class/method → emit a per-class text corpus (DAD pseudo-Java, smali fallback). Feed that corpus to all existing regex detectors in place of the raw-string blob → fixes root cause A and most of B, pure Python.
- A lightweight XREF pass reuses the existing `TAINT_SOURCES` / `DANGEROUS_SINKS` lists over androguard's real call edges → captures DroidBench-style flows without rewriting `ast_analyzer.py`.
- The `javalang` AST path still runs opportunistically when jadx *is* present.

Rejected: full XREF taint rewrite (Option B, too large for first pass); strings-only widening (Option C, leaves B unsolved).

## Phased plan (each phase independently testable)

- **Phase 0 — Measurement first.** `backend/tests/evaluate_recall.py` takes `labels.json` (`apk → [expected CWEs/titles]`), reports recall / precision / F1, reusing scoring logic from `evaluate_precision.py`. Capture a **baseline** before any detection change. Bootstrap around `test.apk` + the existing mock vuln dataset; real labels drop in later.
- **Phase 1 — androguard decompilation seam (load-bearing).** New `AndroguardDecompiler` mirroring `JadxDecompiler`'s interface; unified `get_code_corpus()` preferring jadx → androguard → raw strings, cached. Rewire `main.py` so the AST/taint stage runs whenever *any* corpus exists.
- **Phase 2 — Lightweight XREF taint pass** over androguard's `Analysis` using existing source/sink lists; emits findings with existing CWE tags (CWE-22/78/89/470/…).
- **Phase 3 — Stop dropping real findings.** Replace the hard drop in the mapper with ranking + a `suppressed` boolean flag (nothing deleted; low-confidence demoted but retained in JSON). Recalibrate `compute_confidence` so third-party/test heuristics demote rather than zero out.
- **Phase 4 — LLM-assisted verification (optional gate).** Ollama `LLMClient` as a tie-breaker on medium-confidence findings only — can rescue a demoted finding (recall↑) or reject a bogus one (precision↑). Missing/offline model logs and skips; never changes results silently.
- **Phase 5 — Dependency/Python 3.14 pass.** Confirm `androguard`/`javalang` install on 3.14, bump pins, add to `requirements.txt`.

## Guardrails / YAGNI

- No new web framework, DB, or infra — detection + measurement only.
- LLM stays optional and offline-tolerant.
- Every phase gated by the Phase 0 harness: a change that lowers recall on the labeled set does not ship.

## Success criteria

- Baseline recall recorded, then measurably improved on the labeled set (target: recover the taint-flow CWEs currently missed: CWE-22, CWE-78, CWE-470, CWE-494, CWE-927).
- No regression in precision on the clean mock dataset.
- Pipeline runs end-to-end with neither jadx nor an LLM server present.
