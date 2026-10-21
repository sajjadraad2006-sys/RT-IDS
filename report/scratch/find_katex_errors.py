import re

html = open('report/dist/report.html', encoding='utf-8').read()
matches = list(re.finditer(r'<span class="katex-error"[^>]*title="([^"]+)"[^>]*>([^<]+)</span>', html))
print(f'Total KaTeX error spans: {len(matches)}')
for i, m in enumerate(matches):
    print(f'--- Error {i+1} ---')
    clean_title = m.group(1).encode('ascii', errors='replace').decode('ascii')
    clean_formula = m.group(2).encode('ascii', errors='replace').decode('ascii')
    print('Title:', clean_title)
    print('Formula:', clean_formula)
