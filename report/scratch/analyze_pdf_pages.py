import fitz # PyMuPDF

doc = fitz.open('report/dist/report.pdf')
print(f'Total pages in report.pdf: {len(doc)}')

sparse_pages = []

for page_num in range(len(doc)):
    page = doc[page_num]
    text = page.get_text().strip()
    words = text.split()
    word_count = len(words)
    lines = [l for l in text.splitlines() if l.strip()]
    line_count = len(lines)
    
    # Check if page has very few words or lines
    if word_count < 45:
        sparse_pages.append((page_num + 1, word_count, line_count, text[:150].replace('\n', ' ')))

print(f'\nFound {len(sparse_pages)} sparse pages (under 45 words):')
for p, wc, lc, snippet in sparse_pages:
    print(f'Page {p:2d}: {wc:2d} words, {lc:2d} lines | Snippet: {snippet}')
