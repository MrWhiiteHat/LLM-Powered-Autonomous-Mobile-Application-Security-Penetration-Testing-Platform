"""
SQLite Relational Storage Manager for MSA v2.0 Benchmark Framework.
Maintains exact schema with 12 tables for reproducible research experiments.
"""
import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional


class BenchmarkDatabase:
    """Manages creation, insertion, and querying of benchmark_results.db."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(Path(__file__).resolve().parent.parent.parent / "benchmark_results.db")
        self.db_path = db_path
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Initializes all 12 relational benchmark tables."""
        with self._get_connection() as conn:
            cur = conn.cursor()

            # 1. applications
            cur.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_name TEXT NOT NULL,
                package_name TEXT,
                platform TEXT DEFAULT 'android',
                file_hash_sha256 TEXT UNIQUE,
                file_size_bytes INTEGER,
                category TEXT,
                authorization_type TEXT,
                ground_truth_status TEXT
            );
            """)

            # 2. benchmark_cases
            cur.execute("""
            CREATE TABLE IF NOT EXISTS benchmark_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                benchmark_name TEXT NOT NULL,
                case_name TEXT NOT NULL,
                category TEXT,
                expected_vulnerability TEXT,
                cwe_ids TEXT,
                masvs_ids TEXT,
                mastg_ids TEXT
            );
            """)

            # 3. expected_findings
            cur.execute("""
            CREATE TABLE IF NOT EXISTS expected_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                benchmark_case_id INTEGER,
                cwe_id TEXT,
                severity TEXT,
                description TEXT,
                FOREIGN KEY (benchmark_case_id) REFERENCES benchmark_cases(id)
            );
            """)

            # 4. msa_findings
            cur.execute("""
            CREATE TABLE IF NOT EXISTS msa_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT NOT NULL,
                application_hash TEXT,
                cwe_id TEXT,
                owasp_id TEXT,
                masvs_id TEXT,
                title TEXT,
                severity TEXT,
                confidence REAL,
                detector_module TEXT,
                evidence_location TEXT,
                llm_verdict TEXT,
                timestamp REAL
            );
            """)

            # 5. ground_truth
            cur.execute("""
            CREATE TABLE IF NOT EXISTS ground_truth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_name TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                is_vulnerable INTEGER NOT NULL,
                source_reference TEXT
            );
            """)

            # 6. tool_comparisons
            cur.execute("""
            CREATE TABLE IF NOT EXISTS tool_comparisons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT,
                tool_name TEXT NOT NULL,
                application_name TEXT NOT NULL,
                total_findings INTEGER,
                true_positives INTEGER,
                false_positives INTEGER,
                false_negatives INTEGER,
                precision REAL,
                recall REAL,
                f1_score REAL,
                scan_time_seconds REAL
            );
            """)

            # 7. dynamic_events
            cur.execute("""
            CREATE TABLE IF NOT EXISTS dynamic_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT,
                application_name TEXT,
                hook_name TEXT,
                event_captured INTEGER,
                argument_data TEXT,
                timestamp REAL
            );
            """)

            # 8. rag_results
            cur.execute("""
            CREATE TABLE IF NOT EXISTS rag_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT,
                finding_id TEXT,
                query_text TEXT,
                retrieved_docs_count INTEGER,
                top_source_authority REAL,
                latency_ms REAL
            );
            """)

            # 9. llm_results
            cur.execute("""
            CREATE TABLE IF NOT EXISTS llm_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT,
                model_name TEXT,
                prompt_tokens INTEGER,
                verdict TEXT,
                hallucination_detected INTEGER DEFAULT 0,
                latency_seconds REAL
            );
            """)

            # 10. remediation_results
            cur.execute("""
            CREATE TABLE IF NOT EXISTS remediation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT,
                cwe_id TEXT,
                original_code TEXT,
                patch_code TEXT,
                evaluation_quality TEXT
            );
            """)

            # 11. performance_metrics
            cur.execute("""
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT,
                dataset_name TEXT,
                total_cases INTEGER,
                precision REAL,
                recall REAL,
                f1_score REAL,
                fpr REAL,
                fnr REAL,
                accuracy REAL,
                noise_suppression_pct REAL,
                avg_scan_time_seconds REAL,
                avg_memory_mb REAL
            );
            """)

            # 12. experiment_runs
            cur.execute("""
            CREATE TABLE IF NOT EXISTS experiment_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT UNIQUE NOT NULL,
                timestamp REAL NOT NULL,
                tool_version TEXT NOT NULL,
                msa_version TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                configuration_json TEXT,
                summary_metrics_json TEXT
            );
            """)
            conn.commit()

    def record_experiment_run(
        self,
        experiment_id: str,
        msa_version: str,
        config: Dict[str, Any],
        summary_metrics: Dict[str, Any]
    ) -> None:
        """Records metadata for a completed benchmark experiment run."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT OR REPLACE INTO experiment_runs 
            (experiment_id, timestamp, tool_version, msa_version, dataset_version, configuration_json, summary_metrics_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                experiment_id,
                time.time(),
                "2.0.0",
                msa_version,
                "2026.1",
                json.dumps(config),
                json.dumps(summary_metrics)
            ))
            conn.commit()

    def record_performance_metric(self, experiment_id: str, metric: Any) -> None:
        """Records aggregated dataset metrics."""
        m = metric.to_dict() if hasattr(metric, "to_dict") else metric
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO performance_metrics
            (experiment_id, dataset_name, total_cases, precision, recall, f1_score, fpr, fnr, accuracy, noise_suppression_pct, avg_scan_time_seconds, avg_memory_mb)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                experiment_id,
                m.get("dataset_name"),
                m.get("total_cases", 0),
                m.get("precision", 0.0),
                m.get("recall", 0.0),
                m.get("f1_score", 0.0),
                m.get("false_positive_rate", 0.0),
                m.get("false_negative_rate", 0.0),
                m.get("accuracy", 0.0),
                m.get("noise_suppression_pct", 0.0),
                m.get("avg_scan_time_seconds", 0.0),
                m.get("avg_memory_mb", 0.0)
            ))
            conn.commit()

    def record_tool_comparison(
        self,
        experiment_id: str,
        tool_name: str,
        app_name: str,
        total_findings: int,
        tp: int,
        fp: int,
        fn: int,
        precision: float,
        recall: float,
        f1: float,
        scan_time: float
    ) -> None:
        """Records a head-to-head tool comparison data point."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO tool_comparisons
            (experiment_id, tool_name, application_name, total_findings, true_positives, false_positives, false_negatives, precision, recall, f1_score, scan_time_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                experiment_id, tool_name, app_name, total_findings, tp, fp, fn,
                round(precision, 4), round(recall, 4), round(f1, 4), round(scan_time, 2)
            ))
            conn.commit()

    def record_application(
        self,
        name: str,
        pkg: Optional[str] = None,
        sha256: Optional[str] = None,
        size_bytes: int = 0,
        category: Optional[str] = None,
        auth_type: str = "BENCHMARK",
        gt_status: str = "CANONICAL"
    ) -> int:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT OR IGNORE INTO applications
            (application_name, package_name, file_hash_sha256, file_size_bytes, category, authorization_type, ground_truth_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, pkg, sha256 or name, size_bytes, category, auth_type, gt_status))
            conn.commit()
            return cur.lastrowid or 1

    def record_benchmark_case(
        self,
        benchmark: str,
        case_name: str,
        category: str,
        expected_vuln: str,
        cwes: List[str],
        masvs: List[str],
        mastg: List[str]
    ) -> int:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO benchmark_cases
            (benchmark_name, case_name, category, expected_vulnerability, cwe_ids, masvs_ids, mastg_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (benchmark, case_name, category, expected_vuln, ",".join(cwes), ",".join(masvs), ",".join(mastg)))
            conn.commit()
            return cur.lastrowid or 1

    def record_msa_finding(
        self,
        experiment_id: str,
        app_name: str,
        cwe: str,
        owasp: str,
        masvs: str,
        title: str,
        severity: str,
        confidence: float,
        detector: str,
        location: str,
        llm_verdict: str
    ) -> None:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO msa_findings
            (experiment_id, application_hash, cwe_id, owasp_id, masvs_id, title, severity, confidence, detector_module, evidence_location, llm_verdict, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (experiment_id, app_name, cwe, owasp, masvs, title, severity, confidence, detector, location, llm_verdict, time.time()))
            conn.commit()

    def record_ground_truth(self, app_name: str, cwe_id: str, is_vuln: int, reference: str) -> None:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO ground_truth (application_name, cwe_id, is_vulnerable, source_reference)
            VALUES (?, ?, ?, ?)
            """, (app_name, cwe_id, is_vuln, reference))
            conn.commit()

    def record_remediation_result(self, experiment_id: str, cwe: str, orig_code: str, patch_code: str, quality: str) -> None:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO remediation_results (experiment_id, cwe_id, original_code, patch_code, evaluation_quality)
            VALUES (?, ?, ?, ?, ?)
            """, (experiment_id, cwe, orig_code, patch_code, quality))
            conn.commit()
