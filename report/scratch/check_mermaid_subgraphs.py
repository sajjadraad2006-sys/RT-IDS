import os
import re

for f in sorted(os.listdir('report/chapters')):
    if f.endswith('.md'):
        c = open(os.path.join('report/chapters', f), encoding='utf-8').read()
        blocks = re.findall(r'```mermaid([\s\S]*?)```', c)
        for i, b in enumerate(blocks):
            for line_no, line in enumerate(b.splitlines()):
                line_s = line.strip()
                if line_s.startswith('subgraph '):
                    rest = line_s[9:].strip()
                    # if rest has spaces or special chars and is not quoted with ["..."] or "..."
                    if not (rest.startswith('"') or '[' in rest or '(' in rest):
                        if any(ch in rest for ch in [':', '&', '/', '-', ' ']):
                            print(f'{f} Diagram #{i+1} line {line_no+1}: {line_s}')
