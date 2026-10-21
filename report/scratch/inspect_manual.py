import json

with open('report/results/references_verification.json', 'r', encoding='utf-8') as f:
    v = json.load(f)

for k, r in v['results'].items():
    if r['status'] == 'MANUAL':
        print(f"{k:25} | {r['authority']} | {r['target_title'][:50]}")
