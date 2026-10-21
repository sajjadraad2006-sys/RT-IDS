import re
from pathlib import Path

chapters_dir = Path("report/chapters")
all_figures = []

for ch in sorted(chapters_dir.glob("*.md")):
    text = ch.read_text(encoding="utf-8")
    # find lines with Fig.
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        if re.search(r"Fig(?:\.|ure)\s*\d+", line):
            print(f"{ch.name}:{idx}: {line.strip()[:100]}")
