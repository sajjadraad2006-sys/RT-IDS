c = open('report/build.mjs', encoding='utf-8').read()
for i, l in enumerate(c.splitlines()):
    if any(k in l for k in ['page-break', 'break-before', 'break-after', 'break-inside', 'orphans', 'widows']):
        print(f'{i+1}: {l.strip()}')
