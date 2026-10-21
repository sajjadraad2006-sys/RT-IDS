import re

html = open('report/dist/report.html', encoding='utf-8').read()

cites_left = re.findall(r'\{\{cite:[^}]+\}\}', html)
unknowns = re.findall(r'\[\?\]', html)
print('Unresolved {{cite}}:', cites_left)
print('Unresolved [?]:', unknowns)

refs = re.findall(r'href="#ref-\d+"', html)
print(f'Total clickable IEEE reference links: {len(refs)}')

has_arabic = 'ملخص' in html
print(f'Arabic abstract present: {has_arabic}')

# Check for unrendered KaTeX error spans
katex_errors = re.findall(r'class="katex-error"', html)
print(f'KaTeX rendering errors: {len(katex_errors)}')

# Check tables
table_tags = re.findall(r'<table\b', html)
print(f'HTML tables count: {len(table_tags)}')

# Check figures / diagrams
mermaid_diagrams = re.findall(r'class="mermaid"', html)
print(f'Mermaid diagram blocks: {len(mermaid_diagrams)}')

chart_canvases = re.findall(r'<canvas\b', html)
print(f'Chart.js canvas elements: {len(chart_canvases)}')

if not cites_left and not unknowns and len(refs) > 0 and has_arabic and len(katex_errors) == 0:
    print('ALL AUTOMATED QUALITY GATES PASSED!')
else:
    print('SOME GATES FAILED! Review above metrics.')
