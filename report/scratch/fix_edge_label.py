with open('report/chapters/03-system-architecture.md', 'r', encoding='utf-8') as f:
    text = f.read()

target = '|Drain Batch (B=50)|'
replacement = '|"Drain Batch (B=50)"|'
assert target in text, 'target not found'
text = text.replace(target, replacement)
with open('report/chapters/03-system-architecture.md', 'w', encoding='utf-8') as f:
    f.write(text)
print('Successfully quoted edge label in Chapter 3!')
