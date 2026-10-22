import subprocess
import json
import sys

queries = [
    "model evaluation",
    "imbalanced classification",
    "data leakage",
    "cross-validation",
    "calibration",
    "experiment tracking",
    "reproducibility",
    "benchmark",
    "statistics",
    "bootstrap",
    "confidence interval",
    "data validation",
    "security audit",
    "scientific writing",
    "pdf",
    "report QA",
    "accessibility",
    "link checker",
]

results = {}
for q in queries:
    p = subprocess.run(["npx.cmd", "--yes", "@rmyndharis/antigravity-skills", "search", q], capture_output=True, text=True)
    out = p.stdout.strip()
    results[q] = out
    print(f"=== Query: '{q}' ===")
    lines = [line for line in out.splitlines() if line.strip()]
    for line in lines[:5]:
        print("  ", line)

with open("report/results/catalog_search_pass2.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nDone searching all queries. Saved to report/results/catalog_search_pass2.json")
