import re

with open('report/dist/report.html', 'r', encoding='utf-8') as f:
    html = f.read()

all_ids = set(re.findall(r'id=["\']([^"\']+)["\']', html))
internal_links = re.findall(r'href=["\']#([^"\']+)["\']', html)
broken_links = [l for l in internal_links if l not in all_ids]

print('Total internal links:', len(internal_links))
print('Broken links count:', len(broken_links))
non_ce = [l for l in broken_links if not l.startswith('ce-')]
print('Non-CE broken links:', non_ce)
ce_broken = [l for l in broken_links if l.startswith('ce-')]
print('CE broken count:', len(ce_broken))
print('Distinct broken targets:', set(broken_links))
