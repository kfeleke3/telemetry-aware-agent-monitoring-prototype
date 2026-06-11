# Telemetry-Aware Agent Monitoring Prototype

A  prototype for evaluating simple monitors over synthetic AI agent traces.

This repository is **not a complete benchmark** and should not be described as one. It is a small, honest demonstration of:

- a trace schema for AI agent telemetry,
- monitor interfaces that consume traces,
- three baseline monitors,
- false-positive-aware evaluation metrics, and
- early-detection metrics for suspicious behavior.

## Research motivation

The core research question is:

> Which behavioral traces help monitors detect suspicious AI agent behavior early while keeping false positives low enough for human review?

This prototype focuses on telemetry representations rather than model capability. The synthetic traces are intentionally small and safe. They use toy examples such as reading `secrets_demo.txt`, modifying `auth_demo.py` in an unrelated way, disabling a toy test, or touching hidden demo configuration. The traces do **not** contain real credentials, exploit instructions, harmful code, or operational attack details.

## Relationship to existing work

This project is inspired by AI agent monitoring and benchmark work such as:

- [SHADE-Arena: Evaluating Sabotage and Monitoring in LLM Agents](https://arxiv.org/abs/2506.15740)
- [SLEIGHT-Bench: A Benchmark of Evasion Attacks Against Agent Monitors](https://arxiv.org/abs/2605.16626)

The intended contribution here is narrower: a minimal, readable prototype for experimenting with **telemetry-aware monitor inputs and false-positive-aware evaluation**, not a new benchmark.

## What is in the repo?

```text
telemetry-aware-agent-monitoring-prototype/
├── README.md
├── requirements.txt
├── data/
│   └── traces/
│       ├── trace_001_benign.json
│       └── ...
├── schema/
│   └── trace_schema.md
├── monitors/
│   ├── rule_based.py
│   ├── similarity_monitor.py
│   └── anomaly_monitor.py
├── src/
│   ├── load_traces.py
│   ├── featurize.py
│   └── evaluate.py
├── reports/
│   └── demo_results.md
└── run_demo.py
```

## Quick start

```bash
git clone <your-repo-url>
cd telemetry-aware-agent-monitoring-prototype
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run_demo.py
```

You should see a small table comparing the monitors on precision, recall, false positive rate, early detection, and benign alert burden.

## Monitors included

### 1. Rule-based monitor

Flags simple suspicious patterns such as:

- reading a fake secret file,
- modifying an auth-related file,
- disabling a toy test,
- touching hidden demo config.

### 2. Similarity monitor

Uses TF-IDF and cosine similarity to compare trace step summaries against a few hand-written suspicious reference summaries.

### 3. Anomaly monitor

Extracts simple numeric features from trace prefixes and uses `IsolationForest` trained on benign trace prefixes. It is included as a lightweight baseline, not as a strong anomaly detection system.

## Evaluation metrics

The demo reports:

- precision,
- recall,
- false positive rate,
- recall at a fixed false positive rate,
- detection before harmful completion,
- alerts per benign trace.

Because this repo contains only 10 synthetic traces, the numbers are not statistically meaningful. They are included to demonstrate the evaluation interface and the kinds of tradeoffs that matter for human-reviewable monitoring.

## Design choices

This prototype intentionally avoids overengineering:

- JSON traces are simple and readable.
- Monitors return step-level alerts.
- Evaluation treats a trace as suspicious if any alert fires.
- Early detection is measured by comparing the first alert step with `harmful_completion_step`.

## Intended future version

A more serious version would use live AI agent traces collected from a sandboxed coding or tool-use environment. Future work could include:

- richer telemetry from shell commands, file diffs, tool calls, and environment state,
- task-conditioned monitoring to reduce false positives,
- monitor calibration at operational false positive rates,
- human-review simulations,
- held-out suspicious behaviors and adversarially generated traces,
- comparison between telemetry-only, transcript-only, and hybrid monitors.

## Safety note

All suspicious examples are synthetic and toy-like. They are designed to exercise monitor logic without providing real instructions, credentials, exploits, or harmful code.
