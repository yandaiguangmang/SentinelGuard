"""
Evaluation Metrics (Section IV-C of the paper)
Computes TPR, TNR, FPR, FNR, Precision, Accuracy, F1 Score.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import csv

logger = logging.getLogger(__name__)


@dataclass
class EvalMetrics:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    uncertain: int = 0   # cases where judge returned neither PHISHING nor LEGITIMATE
    total: int = 0

    @property
    def tpr(self) -> float:          # Recall
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def tnr(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def fnr(self) -> float:
        return self.fn / (self.fn + self.tp) if (self.fn + self.tp) > 0 else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tpr

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def update(self, predicted: str, true_label: int) -> None:
        """
        predicted: "PHISHING" | "LEGITIMATE" | other
        true_label: 1 = phishing, 0 = legitimate
        """
        self.total += 1
        if predicted not in ("PHISHING", "LEGITIMATE"):
            self.uncertain += 1
            # Treat as misclassification (same as paper's protocol)
            if true_label == 1:
                self.fn += 1
            else:
                self.fp += 1
            return

        predicted_label = 1 if predicted == "PHISHING" else 0
        if predicted_label == 1 and true_label == 1:
            self.tp += 1
        elif predicted_label == 0 and true_label == 0:
            self.tn += 1
        elif predicted_label == 1 and true_label == 0:
            self.fp += 1
        else:
            self.fn += 1

    def report(self, name: str = "") -> str:
        header = f"=== Evaluation Metrics{' — ' + name if name else ''} ==="
        return (
            f"{header}\n"
            f"  Total samples   : {self.total}\n"
            f"  TP={self.tp}, TN={self.tn}, FP={self.fp}, FN={self.fn}, "
            f"Uncertain={self.uncertain}\n"
            f"\n"
            f"  TPR (Recall)    : {self.tpr:.4f}  ({self.tpr*100:.2f}%)\n"
            f"  TNR             : {self.tnr:.4f}  ({self.tnr*100:.2f}%)\n"
            f"  FPR             : {self.fpr:.4f}  ({self.fpr*100:.2f}%)\n"
            f"  FNR             : {self.fnr:.4f}  ({self.fnr*100:.2f}%)\n"
            f"  Precision       : {self.precision:.4f}  ({self.precision*100:.2f}%)\n"
            f"  Accuracy        : {self.accuracy:.4f}  ({self.accuracy*100:.2f}%)\n"
            f"  F1 Score        : {self.f1:.4f}  ({self.f1*100:.2f}%)\n"
        )

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
            "uncertain": self.uncertain,
            "tpr_recall": round(self.tpr, 4),
            "tnr": round(self.tnr, 4),
            "fpr": round(self.fpr, 4),
            "fnr": round(self.fnr, 4),
            "precision": round(self.precision, 4),
            "accuracy": round(self.accuracy, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class RunRecord:
    """Single prediction record for persistence."""
    sample_id: str
    url: str
    true_label: int
    predicted: str
    confidence: float
    total_rounds: int
    early_termination: bool
    consensus_reached: bool
    elapsed_seconds: float
    judge_reasoning: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


class ResultsLogger:
    """
    Accumulates prediction results and computes metrics.
    Supports incremental saving (CSV + JSON) so you can resume interrupted runs.
    """

    def __init__(self, output_dir: str = "results", run_name: str = "phishdebate"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.run_name = run_name
        self.metrics = EvalMetrics()
        self.records: list[RunRecord] = []

        self._csv_path = self.output_dir / f"{run_name}_predictions.csv"
        self._json_path = self.output_dir / f"{run_name}_predictions.json"
        self._init_csv()

    def _init_csv(self):
        if not self._csv_path.exists():
            with open(self._csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(RunRecord("","",0,"",0,0,False,False,0).__dict__.keys()))
                w.writeheader()

    def log(self, record: RunRecord):
        self.records.append(record)
        self.metrics.update(record.predicted, record.true_label)
        # Append to CSV
        with open(self._csv_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(record.to_dict().keys()))
            w.writerow(record.to_dict())

    def save_json(self):
        data = {
            "run_name": self.run_name,
            "metrics": self.metrics.to_dict(),
            "records": [r.to_dict() for r in self.records],
        }
        with open(self._json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def print_report(self):
        print(self.metrics.report(self.run_name))
        print(f"Results saved to: {self.output_dir}")


def compare_methods(metrics_dict: dict[str, EvalMetrics]) -> str:
    """
    Print a comparison table like Table II in the paper.
    metrics_dict: {"PhishDebate": m1, "Single Agent": m2, "CoT": m3}
    """
    header = f"{'Method':<25} {'Precision':>10} {'Accuracy':>10} {'Recall':>10} {'F1 Score':>10}"
    sep = "-" * len(header)
    rows = [header, sep]
    for name, m in metrics_dict.items():
        rows.append(
            f"{name:<25} {m.precision:>10.4f} {m.accuracy:>10.4f} "
            f"{m.recall:>10.4f} {m.f1:>10.4f}"
        )
    return "\n".join(rows)
