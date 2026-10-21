import urllib.request
import json
import ssl

ctx = ssl._create_unverified_context()

def check_datacite(doi):
    url = f"https://api.datacite.org/dois/{doi}"
    req = urllib.request.Request(url, headers={"User-Agent": "CyberGuard/1.0"})
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
        d = json.loads(r.read())["data"]["attributes"]
        title = d["titles"][0]["title"]
        creators = [c.get("name") or c.get("familyName") for c in d.get("creators", [])]
        year = d.get("publicationYear")
        print(f"DataCite OK: {doi} -> Title: {title} | Creators: {creators} | Year: {year}")

check_datacite("10.48550/arXiv.2305.13860")
check_datacite("10.48550/arXiv.2307.09288")
