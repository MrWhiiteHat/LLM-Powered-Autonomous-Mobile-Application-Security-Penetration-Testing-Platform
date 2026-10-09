"""
AST-Based Taint Flow Analyzer
Uses javalang to parse decompiled Java source into ASTs, then performs
inter-procedural taint tracking, call-graph construction, dead-code pruning,
and structural pattern detection for security vulnerabilities.
Gracefully falls back when javalang is not installed.
"""
import re
from collections import deque
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("ASTAnalyzer")

try:
    import javalang
    from javalang.tree import (
        MethodDeclaration, MethodInvocation, LocalVariableDeclaration,
        CatchClause, ClassDeclaration, VariableDeclarator, Literal,
        MemberReference, BlockStatement,
    )
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False
    logger.warning("javalang not installed. AST analysis disabled. Install with: pip install javalang")


class ASTAnalyzer:
    """Performs AST-level security analysis on decompiled Java source files."""

    # Taint sources: methods that return untrusted / user-controlled data
    TAINT_SOURCES = [
        "getIntent", "getExtras", "getStringExtra", "getData",
        "getQueryParameter", "getText", "getInputStream",
        "getSharedPreferences", "getString", "getParameter",
        "readLine", "getHeader",
    ]

    # Dangerous sinks: methods whose arguments must never be tainted
    DANGEROUS_SINKS = [
        "exec", "rawQuery", "execSQL", "loadUrl",
        "evaluateJavascript", "sendBroadcast", "startActivity",
        "openConnection", "addJavascriptInterface",
        "setJavaScriptEnabled", "write", "delete", "query",
    ]

    # Android lifecycle entry points — roots of the call graph
    ENTRY_POINTS = [
        "onCreate", "onStart", "onResume", "onStartCommand",
        "onReceive", "onBind", "handleMessage", "onNewIntent",
    ]

    def __init__(self, source_dir: Path):
        self.source_dir = source_dir
        self.findings = []
        self.stats = {
            "files_parsed": 0,
            "taint_flows": 0,
            "dead_methods_skipped": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Run the full AST analysis pipeline.

        Returns a dict with ``findings`` and ``ast_stats``.
        """
        if not JAVALANG_AVAILABLE:
            logger.warning("Skipping AST analysis — javalang is not available")
            return {
                "findings": [],
                "ast_stats": {"files_parsed": 0, "taint_flows": 0, "dead_methods_skipped": 0},
            }

        logger.info(f"Starting AST analysis on {self.source_dir}")

        java_files = list(self.source_dir.rglob("*.java"))
        logger.info(f"Found {len(java_files)} Java source files to analyze")

        for java_file in java_files:
            try:
                tree = self._parse_file(java_file)
                if tree is None:
                    continue

                self.stats["files_parsed"] += 1
                rel_path = str(java_file.relative_to(self.source_dir))

                # Build a file-level call graph so we can skip dead code
                call_graph = self._build_call_graph(tree)

                self._trace_taint_flows(tree, rel_path, call_graph)
                self._check_insecure_patterns(tree, rel_path)

            except Exception as e:
                logger.debug(f"Skipping {java_file.name}: {e}")

        logger.info(
            f"AST analysis complete — {self.stats['files_parsed']} files parsed, "
            f"{self.stats['taint_flows']} taint flows, "
            f"{self.stats['dead_methods_skipped']} dead methods skipped"
        )

        return {"findings": self.findings, "ast_stats": self.stats}

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_file(self, java_file: Path) -> Optional[object]:
        """Parse a single Java file with javalang.

        Returns the compilation-unit tree or ``None`` on failure.
        """
        try:
            source = java_file.read_text(encoding="utf-8", errors="ignore")
            tree = javalang.parse.parse(source)
            return tree
        except javalang.parser.JavaSyntaxError as e:
            logger.debug(f"Syntax error in {java_file.name}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Parse error in {java_file.name}: {e}")
            return None

    # ------------------------------------------------------------------
    # Taint-flow tracing
    # ------------------------------------------------------------------

    def _trace_taint_flows(self, tree, filename: str, call_graph: dict):
        """Walk the AST looking for tainted data flowing from a source to a sink.

        For each ``MethodDeclaration`` (skipping dead code):
        1. Collect local variables whose initializers call a TAINT_SOURCE.
        2. Walk subsequent ``MethodInvocation`` nodes; if a call is in
           DANGEROUS_SINKS and any argument references a tainted variable,
           record a finding.
        """
        for _, method_node in tree.filter(MethodDeclaration):
            method_name = method_node.name

            # Skip dead (unreachable) methods
            if self._is_dead_code(method_name, call_graph, self.ENTRY_POINTS):
                self.stats["dead_methods_skipped"] += 1
                continue

            # 1. Collect tainted variables inside this method
            tainted_vars = self._collect_tainted_vars(method_node)
            if not tainted_vars:
                continue

            # 2. Scan for sink calls whose arguments reference tainted vars
            if method_node.body is None:
                continue

            for _, inv_node in method_node.filter(MethodInvocation):
                if inv_node.member not in self.DANGEROUS_SINKS:
                    continue

                # Check if any argument is a tainted variable
                for arg in (inv_node.arguments or []):
                    arg_name = self._resolve_arg_name(arg)
                    if arg_name and arg_name in tainted_vars:
                        source_method = tainted_vars[arg_name]
                        self.stats["taint_flows"] += 1
                        self.findings.append({
                            "title": f"Taint Flow: {source_method} \u2192 {inv_node.member}",
                            "severity": "high",
                            "description": (
                                f"Untrusted data from '{source_method}()' is passed "
                                f"through variable '{arg_name}' into dangerous sink "
                                f"'{inv_node.member}()' in method '{method_name}'. "
                                f"This may lead to injection or data-integrity attacks."
                            ),
                            "category": "ast-taint",
                            "owasp": "M7",
                            "cwe": "CWE-20",
                            "evidence": (
                                f"Source: {source_method}() \u2192 ${arg_name} \u2192 "
                                f"Sink: {inv_node.member}() in {filename}::{method_name}"
                            ),
                            "confidence": "high",
                            "file_path": filename,
                            "method_name": method_name,
                        })
                        break  # one finding per sink call

    def _collect_tainted_vars(self, method_node) -> dict:
        """Return a mapping ``{variable_name: source_method}`` for locals
        whose initialiser calls a TAINT_SOURCE method.
        """
        tainted: dict[str, str] = {}
        if method_node.body is None:
            return tainted

        for _, node in method_node.filter(LocalVariableDeclaration):
            for declarator in (node.declarators or []):
                if not isinstance(declarator, VariableDeclarator):
                    continue
                init = declarator.initializer
                if init is None:
                    continue
                source = self._extract_source_call(init)
                if source:
                    tainted[declarator.name] = source
        return tainted

    def _extract_source_call(self, node) -> Optional[str]:
        """If *node* (or any nested child) is a MethodInvocation whose
        ``member`` is a TAINT_SOURCE, return the member name.
        """
        if isinstance(node, MethodInvocation):
            if node.member in self.TAINT_SOURCES:
                return node.member
            # Check nested invocations (chained calls)
            for arg in (node.arguments or []):
                result = self._extract_source_call(arg)
                if result:
                    return result
            if node.qualifier:
                result = self._extract_source_call(node.qualifier)
                if result:
                    return result
        # Walk generic children via filter (handles arbitrary nesting)
        try:
            if hasattr(node, 'filter'):
                for _, child in node.filter(MethodInvocation):
                    if child is node:
                        continue
                    if child.member in self.TAINT_SOURCES:
                        return child.member
        except Exception:
            pass
        return None

    @staticmethod
    def _resolve_arg_name(arg) -> Optional[str]:
        """Try to extract a simple variable name from an argument AST node."""
        if isinstance(arg, MemberReference):
            return arg.member
        if isinstance(arg, MethodInvocation):
            return None  # not a simple variable
        if hasattr(arg, "name"):
            return arg.name
        return None

    # ------------------------------------------------------------------
    # Call-graph construction & dead-code detection
    # ------------------------------------------------------------------

    def _build_call_graph(self, tree) -> dict:
        """Build a dict ``{method_name: [called_method_names]}`` by walking
        ``MethodDeclaration`` → ``MethodInvocation`` nodes.
        """
        graph: dict[str, list[str]] = {}
        for _, method_node in tree.filter(MethodDeclaration):
            callee_set: set[str] = set()
            for _, inv_node in method_node.filter(MethodInvocation):
                callee_set.add(inv_node.member)
            graph[method_node.name] = list(callee_set)
        return graph

    def _is_dead_code(self, method_name: str, call_graph: dict, entry_points: list) -> bool:
        """Return ``True`` if *method_name* is **not** reachable from any
        entry point via a BFS traversal of *call_graph*.

        Entry-point methods themselves are always considered reachable.
        """
        if method_name in entry_points:
            return False

        # BFS from every entry point
        visited: set[str] = set()
        queue: deque[str] = deque()
        for ep in entry_points:
            if ep in call_graph:
                queue.append(ep)
                visited.add(ep)

        while queue:
            current = queue.popleft()
            for callee in call_graph.get(current, []):
                if callee == method_name:
                    return False
                if callee not in visited and callee in call_graph:
                    visited.add(callee)
                    queue.append(callee)

        return True

    # ------------------------------------------------------------------
    # Insecure-pattern detection (AST-based)
    # ------------------------------------------------------------------

    def _check_insecure_patterns(self, tree, filename: str):
        """Detect structural anti-patterns via the AST.

        1. Empty ``catch`` blocks.
        2. Empty ``checkServerTrusted`` (insecure TrustManager).
        3. Hardcoded crypto keys (variable name contains 'key'/'secret'
           with a string-literal initializer).
        """
        self._check_empty_catch_blocks(tree, filename)
        self._check_insecure_trustmanager(tree, filename)
        self._check_hardcoded_keys(tree, filename)

    def _check_empty_catch_blocks(self, tree, filename: str):
        """Flag ``catch`` clauses with completely empty bodies."""
        try:
            for _, catch_node in tree.filter(CatchClause):
                # An empty body is None or a list with zero statements
                body = catch_node.block if hasattr(catch_node, "block") else None
                if body is None or (isinstance(body, list) and len(body) == 0):
                    self.findings.append({
                        "title": "Empty Exception Handler",
                        "severity": "medium",
                        "description": (
                            f"A catch block in '{filename}' silently swallows exceptions. "
                            f"This can hide critical runtime errors and mask security failures."
                        ),
                        "category": "ast-pattern",
                        "owasp": "M7",
                        "cwe": "CWE-390",
                        "evidence": f"Empty catch clause in {filename}",
                        "confidence": "high",
                        "file_path": filename,
                    })
        except Exception as e:
            logger.debug(f"Error checking empty catch blocks in {filename}: {e}")

    def _check_insecure_trustmanager(self, tree, filename: str):
        """Flag ``checkServerTrusted`` methods with empty bodies —
        a hallmark of certificate-validation bypass.
        """
        try:
            for _, method_node in tree.filter(MethodDeclaration):
                if method_node.name != "checkServerTrusted":
                    continue
                body = method_node.body
                if body is None or (isinstance(body, list) and len(body) == 0):
                    self.findings.append({
                        "title": "Insecure TrustManager Implementation",
                        "severity": "critical",
                        "description": (
                            f"The method 'checkServerTrusted' in '{filename}' has an "
                            f"empty body, effectively trusting all server certificates. "
                            f"This disables TLS certificate validation and exposes the "
                            f"application to Man-in-the-Middle attacks."
                        ),
                        "category": "ast-pattern",
                        "owasp": "M5",
                        "cwe": "CWE-295",
                        "evidence": f"Empty checkServerTrusted() in {filename}",
                        "confidence": "high",
                        "file_path": filename,
                    })
        except Exception as e:
            logger.debug(f"Error checking TrustManager in {filename}: {e}")

    def _check_hardcoded_keys(self, tree, filename: str):
        """Flag local or field variable declarations where the name contains
        ``key`` or ``secret`` and the value is a string literal.
        """
        key_pattern = re.compile(r"(key|secret)", re.IGNORECASE)

        try:
            for _, node in tree.filter(LocalVariableDeclaration):
                for declarator in (node.declarators or []):
                    if not isinstance(declarator, VariableDeclarator):
                        continue
                    if not key_pattern.search(declarator.name):
                        continue
                    init = declarator.initializer
                    if isinstance(init, Literal) and init.value and init.value.startswith('"'):
                        masked = init.value[:8] + "***" if len(init.value) > 12 else "***"
                        self.findings.append({
                            "title": "Hardcoded Cryptographic Key",
                            "severity": "high",
                            "description": (
                                f"Variable '{declarator.name}' in '{filename}' is "
                                f"assigned a string literal that appears to be a "
                                f"cryptographic key or secret. Hardcoded keys can be "
                                f"extracted via reverse engineering."
                            ),
                            "category": "ast-pattern",
                            "owasp": "M1",
                            "cwe": "CWE-321",
                            "evidence": f"{declarator.name} = {masked} in {filename}",
                            "confidence": "high",
                            "file_path": filename,
                        })
        except Exception as e:
            logger.debug(f"Error checking hardcoded keys in {filename}: {e}")
