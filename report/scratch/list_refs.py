import json

with open("report/references.json", "r", encoding="utf-8") as f:
    refs = json.load(f)

print(f"Total entries in references.json: {len(refs)}")
for r in refs:
    print(f"- {r['key']} | type: {r.get('type')} | doi: {r.get('doi', '')}")
