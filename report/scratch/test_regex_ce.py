import re

with open('report/dist/report.html', 'r', encoding='utf-8') as f:
    html = f.read()

pattern = re.compile(r'<td([^>]*)><strong><a href="#ce-(\d+)" class="ce-link">\[CE-(\d+)\]<\/a><\/strong><\/td>')
matches = pattern.findall(html)
print(f"Matched {len(matches)} Code Evidence table cells in Table XXI!")
for m in matches[:5]:
    print(m)
