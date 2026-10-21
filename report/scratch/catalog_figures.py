import re
from pathlib import Path

chapters_dir = Path("report/chapters")
figures = []

for ch in sorted(chapters_dir.glob("*.md")):
    text = ch.read_text(encoding="utf-8")
    # find mermaid blocks
    mermaid_blocks = re.findall(r"```mermaid([\s\S]*?)```", text)
    # find svg blocks
    svg_blocks = re.findall(r"<svg[\s\S]*?<\/svg>", text)
    # find captions
    captions = re.findall(r"(?:<div class=\"figure-caption\">|<b>)(Fig(?:ure|\.)\s*\d+[^<]*)(?:<\/div>|<\/b>)", text)
    
    print(f"\n=== {ch.name} ===")
    print(f"Mermaid blocks: {len(mermaid_blocks)}, SVGs: {len(svg_blocks)}, Captions: {len(captions)}")
    for cap in captions:
        print(f"  - {cap}")

