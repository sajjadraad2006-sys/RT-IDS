import json
import os

cat_path = r'C:\Users\wwwsa\AppData\Local\npm-cache\_npx\7de736acb2e6b880\node_modules\@rmyndharis\antigravity-skills\catalog.json'
with open(cat_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
skills = data.get('skills', [])

queries = [
    'pdf', 'report', 'technical writing', 'documentation', 'academic', 
    'research', 'literature', 'citation', 'diagram', 'mermaid', 
    'chart', 'data visualization', 'html', 'frontend', 'playwright', 
    'puppeteer', 'latex', 'markdown', 'security audit', 'threat modeling', 
    'network', 'ids', 'machine learning', 'evaluation', 'benchmark', 'testing'
]

results = {}
for q in queries:
    terms = q.lower().split()
    matches = []
    for s in skills:
        text = ' '.join([
            s.get('id', ''),
            s.get('name', ''),
            s.get('description', ''),
            ' '.join(s.get('tags', [])),
            s.get('category', '')
        ]).lower()
        if all(t in text for t in terms):
            matches.append({
                'id': s['id'], 
                'name': s['name'], 
                'description': s.get('description', ''),
                'category': s.get('category', '')
            })
    results[q] = matches

os.makedirs('report', exist_ok=True)
with open('report/catalog_search_raw.json', 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2)

print("Search complete. Matches per query:")
for q, m in results.items():
    print(f"Query: '{q}': {len(m)} matches")
    for item in m[:4]:
        print(f"   -> {item['id']} ({item['category']})")
