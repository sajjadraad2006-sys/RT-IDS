import os
import re

for f in sorted(os.listdir('report/chapters')):
    if f.endswith('.md'):
        c = open(os.path.join('report/chapters', f), encoding='utf-8').read()
        blocks = re.findall(r'```mermaid([\s\S]*?)```', c)
        for i, b in enumerate(blocks):
            for l_no, l in enumerate(b.splitlines()):
                for m in re.finditer(r'\|([^|"]+)\|', l):
                    label = m.group(1)
                    if any(ch in label for ch in ['(', ')', '[', ']', ';']):
                        print(f'{f} Diagram #{i+1} line {l_no+1}: unquoted label |{label}|')
