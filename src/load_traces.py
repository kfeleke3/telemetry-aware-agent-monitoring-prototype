"""Utilities for loading synthetic agent traces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_trace(path: str | Path) -> dict[str, Any]:
    """Load one JSON trace file."""
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def load_traces(trace_dir: str | Path) -> list[dict[str, Any]]:
    """Load all trace JSON files from a directory in sorted order."""
    trace_path = Path(trace_dir)
    traces = [load_trace(path) for path in sorted(trace_path.glob("*.json"))]
    if not traces:
        raise FileNotFoundError(f"No JSON traces found in {trace_path}")
    return traces
