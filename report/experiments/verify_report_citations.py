import re
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
chap_dir = REPO_ROOT / "report" / "chapters"

# Regex to catch references like backend/detection/candidate_workflow.py:766-768 or candidate_workflow.py:742-744
pattern = re.compile(r"([a-zA-Z0-9_\-\./\\]+\.(?:py|json|csv|md|txt|html|js|css)):(\d+)(?:-(\d+))?")

citations = []
for f in sorted(chap_dir.glob("*.md")):
    content = f.read_text(encoding="utf-8")
    for line_idx, line in enumerate(content.splitlines(), 1):
        for match in pattern.finditer(line):
            file_path, start_line, end_line = match.groups()
            # Clean path
            clean_path = file_path.replace("\\", "/").lstrip("./")
            # Only consider files belonging to repo
            resolved_file = None
            if (REPO_ROOT / clean_path).exists():
                resolved_file = REPO_ROOT / clean_path
            else:
                # Try finding basename in repo
                bname = Path(clean_path).name
                candidates = list(REPO_ROOT.glob(f"**/{bname}"))
                candidates = [c for c in candidates if not any(skip in c.parts for skip in [".git", "dist", "node_modules", ".agent"])]
                if candidates:
                    resolved_file = candidates[0]

            if resolved_file and resolved_file.is_file():
                citations.append({
                    "chapter": f.name,
                    "chap_line": line_idx,
                    "raw_citation": match.group(0),
                    "file_path": str(resolved_file.relative_to(REPO_ROOT)).replace("\\", "/"),
                    "start_line": int(start_line),
                    "end_line": int(end_line) if end_line else int(start_line),
                    "context": line.strip()
                })

print(f"Total resolved in-repo citations: {len(citations)}")

failures = []
verified = []

for c in citations:
    target_path = REPO_ROOT / c["file_path"]
    lines = target_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    total_lines = len(lines)
    s = c["start_line"]
    e = c["end_line"]
    if s < 1 or s > total_lines:
        failures.append((c, f"Start line {s} out of range (file has {total_lines} lines)"))
    elif e > total_lines:
        failures.append((c, f"End line {e} out of range (file has {total_lines} lines)"))
    else:
        # Extract snippet
        snippet = "\n".join(lines[s-1:e])
        verified.append((c, snippet))

print(f"Verified citations: {len(verified)}")
print(f"Failed citations: {len(failures)}")

for f, reason in failures:
    print(f"FAIL: {f['chapter']}:{f['chap_line']} -> {f['raw_citation']} ({reason})")

# Save detailed log to report/results/citations_audit.json
import json
out_data = {
    "total_citations": len(citations),
    "verified_count": len(verified),
    "failed_count": len(failures),
    "failures": [{"citation": f, "reason": r} for f, r in failures],
    "verified_samples": [{"citation": c, "snippet": s[:200]} for c, s in verified]
}
with open(REPO_ROOT / "report" / "results" / "citations_audit.json", "w", encoding="utf-8") as out_f:
    json.dump(out_data, out_f, indent=2)

print("Saved citations audit to report/results/citations_audit.json")
