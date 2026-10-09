"""
Rigorous Statistical Evaluator for Mobile Security Benchmark.
Implements exact information retrieval & binary classification metrics,
including Wilson score confidence intervals, MCC, FPR/FNR, and Noise Suppression.
"""
import math
from typing import List, Set, Dict, Any, Tuple
from benchmark.adapters.schema import EvaluationMetrics, NormalizedFinding, BenchmarkTarget


class BenchmarkEvaluator:
    """Calculates scientifically defensible precision, recall, and reliability metrics."""

    @staticmethod
    def calculate_wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
        """Calculates Wilson score interval for binomial proportions (e.g. Precision/Recall)."""
        if n == 0:
            return (0.0, 0.0)
        # z-score for 95% confidence interval
        z = 1.95996 if confidence == 0.95 else 1.64485
        p = k / n
        denominator = 1 + (z ** 2) / n
        center = (p + (z ** 2) / (2 * n)) / denominator
        margin = (z * math.sqrt((p * (1 - p) + (z ** 2) / (4 * n)) / n)) / denominator
        lower = max(0.0, center - margin)
        upper = min(1.0, center + margin)
        return (round(lower, 4), round(upper, 4))

    @classmethod
    def evaluate_target(
        cls,
        target: BenchmarkTarget,
        findings: List[NormalizedFinding]
    ) -> Dict[str, Any]:
        """
        Evaluates findings against a single target with known ground truth.
        Distinguishes between supported vs unsupported tests and clean apps.
        """
        expected_cwes: Set[str] = set(target.cwe)
        detected_cwes: Set[str] = {f.cwe_id for f in findings if f.llm_verdict != "FALSE_POSITIVE"}

        # If ground truth is unknown (e.g. real-world apps), do not compute artificial TP/FP
        if not target.ground_truth or target.ground_truth_status == "UNKNOWN":
            return {
                "application": target.application,
                "benchmark": target.benchmark,
                "ground_truth_available": False,
                "detected_findings": len(findings),
                "unique_cwes_detected": list(detected_cwes),
                "tp": 0, "fp": 0, "fn": 0, "tn": 0
            }

        # Clean/benign target (expected_cwes is empty)
        if not expected_cwes:
            if not detected_cwes:
                # Perfectly clean app, zero false positives
                return {
                    "application": target.application,
                    "benchmark": target.benchmark,
                    "ground_truth_available": True,
                    "tp": 0, "fp": 0, "fn": 0, "tn": 1,
                    "detected_cwes": list(detected_cwes)
                }
            else:
                # Benign app flagged with alerts -> False Positives
                return {
                    "application": target.application,
                    "benchmark": target.benchmark,
                    "ground_truth_available": True,
                    "tp": 0, "fp": len(detected_cwes), "fn": 0, "tn": 0,
                    "detected_cwes": list(detected_cwes)
                }

        # Vulnerable target
        matched_cwes = expected_cwes.intersection(detected_cwes)
        unmatched_expected = expected_cwes.difference(detected_cwes)
        unmatched_detected = detected_cwes.difference(expected_cwes)

        tp = len(matched_cwes)
        fn = len(unmatched_expected)
        fp = len(unmatched_detected)
        tn = 0

        return {
            "application": target.application,
            "benchmark": target.benchmark,
            "ground_truth_available": True,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "matched_cwes": list(matched_cwes),
            "missed_cwes": list(unmatched_expected),
            "spurious_cwes": list(unmatched_detected)
        }

    @classmethod
    def aggregate_metrics(
        cls,
        dataset_name: str,
        results_list: List[Dict[str, Any]],
        raw_fp: int = 0,
        final_fp: int = 0,
        scan_times: List[float] = None,
        memories: List[float] = None
    ) -> EvaluationMetrics:
        """Aggregates per-target evaluation results into standard IEEE metrics."""
        tp = sum(r.get("tp", 0) for r in results_list if r.get("ground_truth_available"))
        fp = sum(r.get("fp", 0) for r in results_list if r.get("ground_truth_available"))
        fn = sum(r.get("fn", 0) for r in results_list if r.get("ground_truth_available"))
        tn = sum(r.get("tn", 0) for r in results_list if r.get("ground_truth_available"))

        total_cases = tp + fp + fn + tn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        accuracy = (tp + tn) / total_cases if total_cases > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # Matthews Correlation Coefficient
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = ((tp * tn) - (fp * fn)) / denom if denom > 0 else 0.0

        # Noise suppression
        noise_suppression = ((raw_fp - final_fp) / raw_fp * 100.0) if raw_fp > 0 else 0.0

        # Confidence intervals
        prec_ci = cls.calculate_wilson_ci(tp, tp + fp)
        rec_ci = cls.calculate_wilson_ci(tp, tp + fn)

        avg_time = sum(scan_times) / len(scan_times) if scan_times else 0.0
        avg_mem = sum(memories) / len(memories) if memories else 0.0

        return EvaluationMetrics(
            dataset_name=dataset_name,
            total_cases=total_cases,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            accuracy=round(accuracy, 4),
            specificity=round(specificity, 4),
            mcc=round(mcc, 4),
            raw_false_positives=raw_fp,
            final_false_positives=final_fp,
            noise_suppression_pct=round(noise_suppression, 2),
            avg_scan_time_seconds=round(avg_time, 2),
            avg_memory_mb=round(avg_mem, 2),
            precision_ci=prec_ci,
            recall_ci=rec_ci
        )
