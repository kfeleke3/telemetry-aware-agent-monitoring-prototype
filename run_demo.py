"""Run the synthetic telemetry-aware monitoring demo."""

from __future__ import annotations

from pathlib import Path

from monitors.anomaly_monitor import AnomalyMonitor
from monitors.rule_based import RuleBasedMonitor
from monitors.similarity_monitor import SimilarityMonitor
from src.evaluate import evaluate_monitors
from src.load_traces import load_traces


TRACE_DIR = Path("data/traces")
FIXED_FPR = 0.20


def _fmt(value: float) -> str:
    return f"{value:.2f}"


def print_results_table(results: list[dict]) -> None:
    headers = [
        "Monitor",
        "Precision",
        "Recall",
        "FPR",
        f"Recall@FPR≤{FIXED_FPR:.2f}",
        "EarlyDetect",
        "Alerts/Benign",
    ]
    rows = []
    recall_at_key = f"recall_at_fpr_{FIXED_FPR:.2f}"
    for row in results:
        rows.append(
            [
                row["monitor"],
                _fmt(row["precision"]),
                _fmt(row["recall"]),
                _fmt(row["false_positive_rate"]),
                _fmt(row[recall_at_key]),
                _fmt(row["early_detection_rate"]),
                _fmt(row["alerts_per_benign_trace"]),
            ]
        )

    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(str(cell))) for width, cell in zip(widths, row)]

    def line(cells: list[str]) -> str:
        return " | ".join(str(cell).ljust(width) for cell, width in zip(cells, widths))

    print(line(headers))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(line(row))


def main() -> None:
    traces = load_traces(TRACE_DIR)

    monitors = [
        RuleBasedMonitor(),
        SimilarityMonitor(),
        AnomalyMonitor(random_state=42).fit(traces),
    ]

    results = evaluate_monitors(monitors, traces, fixed_fpr=FIXED_FPR)
    print("Telemetry-aware agent monitoring prototype")
    print(f"Loaded {len(traces)} synthetic traces from {TRACE_DIR}\n")
    print_results_table(results)
    print("\nNote: this is a tiny synthetic demo, not a benchmark.")


if __name__ == "__main__":
    main()
