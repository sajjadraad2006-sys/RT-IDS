import re
from pathlib import Path

chapters_dir = Path("report/chapters")
for ch in sorted(chapters_dir.glob("*.md")):
    text = ch.read_text(encoding="utf-8")
    for m in re.finditer(r"\[CE-(\d+)[^\]]*\]", text):
        num = int(m.group(1))
        if num > 45:
            # find surrounding text
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            print(f"{ch.name}: CE-{num:02d}: {text[start:end].strip()}")
