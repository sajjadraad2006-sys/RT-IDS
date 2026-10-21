import re

for chap in ['04-implementation-analysis.md', '07-security-and-safety-analysis.md', '11-references-and-appendices.md']:
    path = f'report/chapters/{chap}'
    lines = open(path, encoding='utf-8').read().splitlines()
    in_block = False
    for i, l in enumerate(lines):
        if '$$' in l:
            # toggles
            pass
        # Count single $ on this line
        cleaned = re.sub(r'\$\$', '', l)
        cnt = cleaned.count('$')
        if cnt % 2 != 0:
            print(f'{chap}: Line {i+1} has odd single $ ({cnt}): {l}')
