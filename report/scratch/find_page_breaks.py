import os

for f in sorted(os.listdir('report/chapters')):
    if f.endswith('.md'):
        c = open(os.path.join('report/chapters', f), encoding='utf-8').read()
        cnt = c.count('class="page-break"') + c.count("class='page-break'")
        if cnt > 0:
            print(f'{f}: {cnt} explicit page-breaks')
