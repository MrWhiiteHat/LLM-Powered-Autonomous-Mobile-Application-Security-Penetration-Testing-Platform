"""
Standard Data Schema and Normalized Models for MSA Benchmark & Evaluation Framework.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum
import json
import time


class BenchmarkAuthorization(str, Enum):
    BENCHMARK = "BENCHMARK"
    AUTHORIZED = "AUTHORIZED"
    RESEARCH_DATASET = "RESEARCH_DATASET"


class TestStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class DetectionMode(str, Enum):
    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    BOTH = "BOTH"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class RemediationQuality(str, Enum):
    CORRECT = "CORRECT"
    PARTIALLY_CORRECT = "PARTIALLY_CORRECT"
    INCORRECT = "INCORRECT"
    UNSAFE = "UNSAFE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class BenchmarkTarget:
    """Metadata describing a test application or benchmark sample."""
    benchmark: str
    application: str
    version: str
    platform: str
    package: str
    category: str
    expected_vulnerability: str
    cwe: List[str] = field(default_factory=list)
    masvs: List[str] = field(default_factory=list)
    mastg: List[str] = field(default_factory=list)
    ground_truth: bool = True
    authorized: bool = True
    authorization_type: BenchmarkAuthorization = BenchmarkAuthorization.BENCHMARK
    apk_path: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    size_bytes: int = 0
    ground_truth_status: str = "VERIFIED"  # VERIFIED or UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["authorization_type"] = self.authorization_type.value
        return d


@dataclass
class NormalizedFinding:
    """Canonical representation of an individual security finding."""
    finding_id: str
    target_app: str
    cwe_id: str
    owasp_id: str
    masvs_id: str
    title: str
    severity: str
    confidence: float
    detector_module: str
    evidence_location: str
    evidence_snippet: str
    is_taint_flow: bool = False
    source_sink_path: Optional[List[str]] = None
    rag_retrieved_docs: int = 0
    llm_verdict: str = "UNAUDITED"  # VULNERABLE, FALSE_POSITIVE, UNAUDITED
    remediation_patch: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationMetrics:
    """Statistical evaluation metrics for a specific experiment or dataset."""
    dataset_name: str
    total_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    accuracy: float
    specificity: float
    mcc: float
    raw_false_positives: int = 0
    final_false_positives: int = 0
    noise_suppression_pct: float = 0.0
    avg_scan_time_seconds: float = 0.0
    avg_memory_mb: float = 0.0
    precision_ci: tuple = (0.0, 0.0)  # 95% Wilson confidence interval
    recall_ci: tuple = (0.0, 0.0)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
