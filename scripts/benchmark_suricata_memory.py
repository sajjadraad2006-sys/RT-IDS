#!/usr/bin/env python3
"""Suricata EVE ingestion memory benchmark — subprocess-isolated measurements.

Measures memory consumption of the *complete* FastAPI/TestClient request path:
parser + database persistence + response serialization.

Each fixture runs in a fresh subprocess to isolate RSS measurements.
Does NOT measure production Uvicorn/socket overhead or UploadFile disk spooling.
"""
from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def generate_fixture(target: Path, count: int) -> dict:
    """Write a deterministic EVE NDJSON fixture and return metadata."""
    with open(target, "w") as f:
        for i in range(count):
            alert = {
                "timestamp": f"2026-08-30T10:{i // 3600 % 24:02d}:{i // 60 % 60:02d}.{i % 60:06d}+0000",
                "flow_id": 100000 + i,
                "event_type": "alert",
                "src_ip": f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}",
                "src_port": 40000 + (i % 20000),
                "dest_ip": "198.51.100.42",
                "dest_port": 443,
                "proto": "TCP",
                "app_proto": "tls",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 3000000 + i,
                    "rev": 1,
                    "signature": f"Benchmark Alert {i}",
                    "category": "Benchmark",
                    "severity": 1 + (i % 4),
                    "metadata": {
                        "mitre_technique_id": [f"T{1000 + (i % 100):04d}"],
                        "mitre_tactic_id": ["TA0011"],
                    },
                },
            }
            f.write(json.dumps(alert, separators=(",", ":")) + "\n")
    stat = target.stat()
    return {
        "path": str(target),
        "size_bytes": stat.st_size,
        "line_count": count,
    }


CHILD_SCRIPT = r'''
import json, os, resource, sys, time, tracemalloc, tempfile
from pathlib import Path

fixture_path = sys.argv[1]
sensor_id = sys.argv[2]

# Isolate CG_DB_PATH
_tmpdir = tempfile.mkdtemp(prefix="cg-bench-")
os.environ["CG_DB_PATH"] = str(Path(_tmpdir) / "bench.sqlite")

# Measure starting RSS
rss_start = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KB on Linux

tracemalloc.start()

from backend.db.init_db import init_all
init_all()

from fastapi.testclient import TestClient
from backend.main import app
from backend.limiter import limiter
limiter._limiter.storage.reset()

client = TestClient(app)

with open(fixture_path, "rb") as f:
    payload = f.read()

rss_before_ingest = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
t0 = time.perf_counter()

res = client.post(
    f"/api/events/suricata/upload?sensor_id={sensor_id}",
    files={"file": ("bench.json", payload, "application/json")},
)

elapsed = time.perf_counter() - t0
rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
_, peak_tracemalloc = tracemalloc.get_traced_memory()
tracemalloc.stop()

report = res.json() if res.status_code == 200 else {"error": res.status_code}

result = {
    "status_code": res.status_code,
    "process_startup_rss_kb": rss_start,
    "rss_before_ingest_kb": rss_before_ingest,
    "rss_peak_kb": rss_after,
    "rss_delta_kb": rss_after - rss_before_ingest,
    "tracemalloc_peak_bytes": peak_tracemalloc,
    "tracemalloc_peak_mb": round(peak_tracemalloc / (1024 * 1024), 2),
    "elapsed_seconds": round(elapsed, 3),
    "fixture_size_bytes": len(payload),
    "fixture_size_mb": round(len(payload) / (1024 * 1024), 2),
    "total_parsed": report.get("total_parsed"),
    "accepted": report.get("accepted"),
    "rejected_lines": report.get("rejected_lines"),
    "persisted": report.get("persisted"),
    "returned_events_count": report.get("returned_events_count"),
    "omitted_due_to_persistence_cap": report.get("omitted_due_to_persistence_cap"),
    "alert_events_accepted": report.get("alert_events_accepted"),
    "batch_size": 500,  # BATCH_SIZE in events.py
    "response_cap": report.get("caps", {}).get("max_return_events"),
    "persistence_cap": report.get("caps", {}).get("max_persist_events"),
}

# Throughput
if elapsed > 0 and report.get("accepted"):
    result["throughput_events_per_sec"] = round(report["accepted"] / elapsed, 1)
    result["throughput_mb_per_sec"] = round(len(payload) / (1024 * 1024) / elapsed, 2)

print(json.dumps(result))
'''


def run_benchmark(fixture_path: str, sensor_id: str, label: str) -> dict:
    """Run benchmark in a fresh subprocess."""
    result = subprocess.run(
        [sys.executable, "-c", CHILD_SCRIPT, fixture_path, sensor_id],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
        timeout=300,
    )
    if result.returncode != 0:
        print(f"[{label}] CHILD STDERR:\n{result.stderr}", file=sys.stderr)
        return {"error": f"exit code {result.returncode}", "stderr": result.stderr[-500:]}
    try:
        return json.loads(result.stdout.strip().split("\n")[-1])
    except (json.JSONDecodeError, IndexError):
        return {"error": "failed to parse child output", "stdout": result.stdout[-500:]}


def main():
    project_root = Path(__file__).resolve().parent.parent
    tmpdir = tempfile.mkdtemp(prefix="cg-bench-fixtures-")

    print("=" * 80)
    print("CyberGuard Suricata EVE Ingestion Memory Benchmark")
    print("=" * 80)
    print()
    print("MEASUREMENT SCOPE: Complete FastAPI/TestClient request")
    print("  Includes: EVE parser, ATT&CK validation, SQLite persistence,")
    print("            batch flush with expunge, response serialization")
    print("  Excludes: Uvicorn socket overhead, UploadFile disk spooling,")
    print("            production connection pooling")
    print()
    print("Each fixture runs in a FRESH subprocess for RSS isolation.")
    print()

    # Generate fixtures with accurate size labels
    fixtures = [
        ("0.3MB", 800, "bench-small"),
        ("7.9MB", 20000, "bench-large"),
    ]

    results = {}
    for label, count, sensor in fixtures:
        fixture_path = Path(tmpdir) / f"{sensor}.json"
        meta = generate_fixture(fixture_path, count)
        print(f"--- {label} fixture ({count} events, {meta['size_bytes']/1024/1024:.1f} MB) ---")

        result = run_benchmark(str(fixture_path), sensor, label)
        results[label] = {**meta, **result}

        if "error" in result:
            print(f"  ERROR: {result['error']}")
        else:
            print(f"  Status:              {result.get('status_code')}")
            print(f"  Process Startup RSS: {result.get('process_startup_rss_kb', 0):,} KB")
            print(f"  RSS Before Ingest:   {result.get('rss_before_ingest_kb', 0):,} KB")
            print(f"  RSS Peak:            {result.get('rss_peak_kb', 0):,} KB")
            print(f"  RSS Delta:           {result.get('rss_delta_kb', 0):,} KB")
            print(f"  Tracemalloc Peak:    {result.get('tracemalloc_peak_mb', 0):.2f} MB")
            print(f"  Elapsed:             {result.get('elapsed_seconds', 0):.3f}s")
            print(f"  Parsed/Accepted:     {result.get('total_parsed')}/{result.get('accepted')}")
            print(f"  Persisted/Returned:  {result.get('persisted')}/{result.get('returned_events_count')}")
            print(f"  Omitted by Cap:      {result.get('omitted_due_to_persistence_cap')}")
            tp = result.get("throughput_events_per_sec")
            if tp:
                print(f"  Throughput:          {tp:,.1f} events/s, {result.get('throughput_mb_per_sec', 0):.2f} MB/s")
        print()

    # Save JSON results
    out_path = project_root / "benchmark_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full results written to: {out_path}")

    print()
    print("DISCLAIMER: These measurements reflect the TestClient code path,")
    print("not a production Uvicorn deployment. RSS delta includes the SQLite")
    print("WAL, response serialization buffer, and Python GC overhead.")
    print("Do not describe this as constant-space for the complete service")
    print("if only the parser heap was measured.")


if __name__ == "__main__":
    main()
