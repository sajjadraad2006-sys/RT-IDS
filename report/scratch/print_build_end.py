c = open('report/build.mjs', encoding='utf-8').read()
lines = c.splitlines()
for i in range(670, len(lines)):
    clean = lines[i].encode('ascii', errors='replace').decode('ascii')
    print(f'{i+1}: {clean}')
