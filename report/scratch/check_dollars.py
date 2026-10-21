import os

for f in sorted(os.listdir('report/chapters')):
    if f.endswith('.md'):
        c = open(os.path.join('report/chapters', f), encoding='utf-8').read()
        cnt_block = c.count('$$')
        cnt_inline = c.count('$') - (cnt_block * 2)
        print(f'{f}: {cnt_block} block $$ ({cnt_block // 2} pairs, remainder {cnt_block % 2}), {cnt_inline} inline $')
        if cnt_block % 2 != 0:
            print(f'  --> UNBALANCED BLOCK $$ IN {f}!')
        if cnt_inline % 2 != 0:
            print(f'  --> UNBALANCED INLINE $ IN {f}!')
