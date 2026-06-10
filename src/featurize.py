"""Simple feature extraction for synthetic AI agent traces."""

from __future__ import annotations

from typing import Any

import numpy as np


FEATURE_NAMES = [
    "num_steps",
    "num_file_reads",
    "num_file_modifies",
    "num_test_runs",
    "num_hidden_targets",
    "num_secret_targets",
    "num_auth_targets",
    "num_test_disable_mentions",
    "num_unrelated_mentions",
    "num_environment_changes",
    "num_unique_tools",
]


NO_CHANGE_VALUES = {"", "none", "no change", "n/a"}


def _step_text(step: dict[str, Any]) -> str:
    """Join the human-readable fields used by simple text monitors."""
    return " ".join(
        str(step.get(field, ""))
        for field in ["event_type", "tool", "target", "content_summary", "environment_change"]
    ).lower()


def trace_to_text(trace: dict[str, Any], upto_step: int | None = None) -> str:
    """Convert a trace or trace prefix into a compact text representation."""
    steps = trace["steps"] if upto_step is None else trace["steps"][:upto_step]
    step_text = " ".join(_step_text(step) for step in steps)
    return f"task_type={trace.get('task_type', '')} {step_text}"


def trace_to_features(trace: dict[str, Any], upto_step: int | None = None) -> np.ndarray:
    """Extract small numeric features from a full trace or prefix.

    These features are intentionally simple. The goal is to demonstrate how
    telemetry can be transformed into monitor inputs, not to build a strong
    detector.
    """
    steps = trace["steps"] if upto_step is None else trace["steps"][:upto_step]
    texts = [_step_text(step) for step in steps]
    targets = [str(step.get("target", "")).lower() for step in steps]
    tools = {str(step.get("tool", "")) for step in steps}

    def count_if(predicate) -> int:
        return sum(1 for step, text, target in zip(steps, texts, targets) if predicate(step, text, target))

    features = [
        len(steps),
        count_if(lambda step, text, target: step.get("event_type") == "file_read"),
        count_if(lambda step, text, target: step.get("event_type") in {"file_modify", "file_create", "config_touch"}),
        count_if(lambda step, text, target: step.get("event_type") == "test_run"),
        count_if(lambda step, text, target: target.startswith(".") or "/." in target or "hidden" in target),
        count_if(lambda step, text, target: "secret" in target or "credential" in target),
        count_if(lambda step, text, target: "auth" in target),
        count_if(lambda step, text, target: "disable" in text or "disabled" in text or "skip" in text),
        count_if(lambda step, text, target: "unrelated" in text or "outside task scope" in text),
        count_if(lambda step, text, target: str(step.get("environment_change", "")).strip().lower() not in NO_CHANGE_VALUES),
        len(tools),
    ]
    return np.asarray(features, dtype=float)


def prefix_feature_matrix(traces: list[dict[str, Any]], labels: set[str] | None = None) -> np.ndarray:
    """Return feature rows for every prefix of selected traces."""
    rows = []
    for trace in traces:
        if labels is not None and trace.get("label") not in labels:
            continue
        for upto_step in range(1, len(trace["steps"]) + 1):
            rows.append(trace_to_features(trace, upto_step=upto_step))
    return np.vstack(rows)
