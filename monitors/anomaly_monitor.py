"""Small IsolationForest anomaly monitor for synthetic trace telemetry."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from src.featurize import prefix_feature_matrix, trace_to_features


class AnomalyMonitor:
    """Anomaly baseline trained on benign trace prefixes.

    Higher scores mean more anomalous. The default threshold is calibrated from
    benign prefix scores, which keeps the demo false-positive-aware without
    pretending this tiny dataset is enough for real calibration.
    """

    name = "isolation_forest"

    def __init__(self, random_state: int = 7, percentile_threshold: float = 85.0) -> None:
        self.random_state = random_state
        self.percentile_threshold = percentile_threshold
        self.model = IsolationForest(contamination="auto", random_state=random_state)
        self.default_threshold: float | None = None

    def fit(self, traces: list[dict[str, Any]]) -> "AnomalyMonitor":
        """Fit on benign trace prefixes only."""
        x_train = prefix_feature_matrix(traces, labels={"benign"})
        self.model.fit(x_train)

        # decision_function is larger for normal points. Negating it gives a
        # simple anomaly score where larger means more unusual.
        benign_scores = -self.model.decision_function(x_train)
        self.default_threshold = float(np.percentile(benign_scores, self.percentile_threshold))
        return self

    def _score_prefix(self, trace: dict[str, Any], upto_step: int) -> float:
        features = trace_to_features(trace, upto_step=upto_step).reshape(1, -1)
        return float(-self.model.decision_function(features)[0])

    def score_trace(self, trace: dict[str, Any]) -> float:
        """Return maximum anomaly score over trace prefixes."""
        scores = [self._score_prefix(trace, i) for i in range(1, len(trace["steps"]) + 1)]
        return max(scores) if scores else 0.0

    def alert_trace(self, trace: dict[str, Any], threshold: float | None = None) -> list[dict[str, Any]]:
        """Return alerts for anomalous trace prefixes."""
        if self.default_threshold is None:
            raise RuntimeError("AnomalyMonitor must be fit before alerting.")

        threshold = self.default_threshold if threshold is None else threshold
        alerts = []
        for upto_step in range(1, len(trace["steps"]) + 1):
            score = self._score_prefix(trace, upto_step)
            if score >= threshold:
                alerts.append(
                    {
                        "step": trace["steps"][upto_step - 1]["step"],
                        "score": score,
                        "reason": "anomalous_trace_prefix_features",
                    }
                )
        return alerts
