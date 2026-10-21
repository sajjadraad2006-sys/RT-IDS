"""Experiment P3.c: Detection Pipeline Benchmarks & Routing Distribution.

Measures:
1. Per-row latency distribution (P50, P90, P95, P99, mean, std, min, max)
2. Batch throughput vs batch size (batch sizes: 1, 10, 50, 100, 250, 500, 1000, 2000)
3. Memory delta per batch execution
4. Deterministic routing distribution on the bundled fixture (2000 rows)
5. Cross-tabulation of routes vs ground truth labels
"""
import datetime
import json
import os
import platform
import sys
import time
import tracemalloc
from pathlib import Path

import numpy as np
import pandas as pd

root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from backend.api.detection import _get_pipeline
from backend.detection.features import FEATURE_NAMES


def get_environment_info():
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "cpu_count": os.cpu_count() or 1,
    }


def run_pipeline_benchmarks():
    print("[*] Loading Detection Pipeline via integrity verification...")
    pipeline = _get_pipeline()

    fixture_path = root_dir / "cyberguard" / "datasets" / "cicids2017" / "sample_traffic.csv"
    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture not found at {fixture_path}")

    df = pd.read_csv(fixture_path)
    labels = df["Label"].tolist()
    feature_rows = df[FEATURE_NAMES].to_dict(orient="records")
    n_total = len(feature_rows)

    results = {
        "metadata": {
            "experiment": "P3.c_pipeline_benchmarks",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "fixture_rows": n_total,
            "environment": get_environment_info(),
            "pipeline_version": pipeline.artifact_pipeline_version,
            "routing_schema": pipeline.artifact_routing_schema_version,
            "supported_classes": list(pipeline.supported_labels) if pipeline.supported_labels else [],
        },
        "per_row_latency": {},
        "batch_scaling": [],
        "routing_distribution": {},
        "confusion_contingency": {},
    }

    # 1. Per-row latency evaluation (1000 single-row runs)
    print("[*] Measuring per-row inference latency across 1000 flows...")
    single_latencies_ms = []
    # Warmup
    for i in range(50):
        pipeline.detect(feature_rows[i % n_total])

    for i in range(1000):
        row = feature_rows[i % n_total]
        t0 = time.perf_counter()
        alert = pipeline.detect(row)
        t1 = time.perf_counter()
        single_latencies_ms.append((t1 - t0) * 1000.0)

    lat_arr = np.array(single_latencies_ms)
    results["per_row_latency"] = {
        "sample_count": len(single_latencies_ms),
        "mean_ms": round(float(np.mean(lat_arr)), 3),
        "std_ms": round(float(np.std(lat_arr)), 3),
        "min_ms": round(float(np.min(lat_arr)), 3),
        "p50_ms": round(float(np.percentile(lat_arr, 50)), 3),
        "p90_ms": round(float(np.percentile(lat_arr, 90)), 3),
        "p95_ms": round(float(np.percentile(lat_arr, 95)), 3),
        "p99_ms": round(float(np.percentile(lat_arr, 99)), 3),
        "max_ms": round(float(np.max(lat_arr)), 3),
    }

    # 2. Batch throughput vs Batch Size
    print("[*] Measuring batch latency and throughput scaling...")
    batch_sizes = [1, 10, 50, 100, 250, 500, 1000, 2000]
    for b_size in batch_sizes:
        batch_slice = feature_rows[:b_size]
        tracemalloc.start()
        t0 = time.perf_counter()
        alerts = pipeline.detect_batch(batch_slice)
        t1 = time.perf_counter()
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        elapsed_sec = t1 - t0
        throughput = b_size / elapsed_sec if elapsed_sec > 0 else 0.0
        per_item_ms = (elapsed_sec / b_size) * 1000.0

        results["batch_scaling"].append({
            "batch_size": b_size,
            "elapsed_seconds": round(elapsed_sec, 5),
            "throughput_flows_per_sec": round(throughput, 2),
            "latency_per_item_ms": round(per_item_ms, 4),
            "peak_memory_kb": round(peak_mem / 1024.0, 2),
        })

    # 3. Full routing distribution and Contingency Table on the 2000 rows
    print("[*] Running full 2000-row fixture evaluation for routing distribution...")
    all_alerts = pipeline.detect_batch(feature_rows)

    routes_count = {}
    verdicts_count = {}
    contingency = {}

    for row_idx, alert in enumerate(all_alerts):
        route = alert.route
        verdict = alert.type
        true_label = labels[row_idx]

        routes_count[route] = routes_count.get(route, 0) + 1
        verdicts_count[verdict] = verdicts_count.get(verdict, 0) + 1

        if true_label not in contingency:
            contingency[true_label] = {}
        contingency[true_label][route] = contingency[true_label].get(route, 0) + 1

    results["routing_distribution"] = {
        "routes": routes_count,
        "verdicts": verdicts_count,
    }
    results["confusion_contingency"] = contingency

    out_dir = root_dir / "report" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "pipeline_benchmarks.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[*] Pipeline benchmarks complete. Saved to {out_path}")
    print(f"[*] Per-row latency: P50={results['per_row_latency']['p50_ms']} ms, P95={results['per_row_latency']['p95_ms']} ms, P99={results['per_row_latency']['p99_ms']} ms")
    print("[*] Batch Scaling Summary:")
    for b in results["batch_scaling"]:
        print(f"  Batch {b['batch_size']:4}: {b['throughput_flows_per_sec']:8.1f} flows/sec ({b['latency_per_item_ms']:.3f} ms/flow), Peak Mem: {b['peak_memory_kb']} KB")
    print("[*] Contingency (True Label vs Route):")
    for lbl, r_dict in contingency.items():
        print(f"  {lbl:10}: {r_dict}")


if __name__ == "__main__":
    run_pipeline_benchmarks()
