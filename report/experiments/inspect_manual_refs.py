import json
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from bs4 import BeautifulSoup

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
refs_file = REPO_ROOT / "report" / "references.json"
verif_file = REPO_ROOT / "report" / "results" / "references_verification.json"

with open(refs_file, "r", encoding="utf-8") as f:
    refs = json.load(f)

with open(verif_file, "r", encoding="utf-8") as f:
    verif = json.load(f)

manual_keys = [
    "arp2022dos",
    "pendlebury2019tesseract",
    "roesch1999snort",
    "mccanne1993bsd",
    "suricata2024engine",
    "strom2018mitre",
    "kaloroumakis2021d3fend",
    "shostack2014threat",
    "barrett2010smtlib",
    "owasp2023top10llm",
    "iec62443standard",
    "modbus2012spec",
    "opcfoundation2022spec"
]

print(f"Checking {len(manual_keys)} manual references...")

# Context with default TLS verification (never disable TLS verification)
ctx = ssl.create_default_context()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

results = {}
for r in refs:
    k = r["key"]
    if k in manual_keys:
        url = r.get("url")
        title = r.get("title")
        print(f"\n--- Checking {k} ---")
        print(f"Target Title: {title}")
        print(f"URL: {url}")
        
        status_code = None
        seen_title = None
        error_msg = None
        
        if url:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    status_code = resp.status
                    content_type = resp.headers.get("Content-Type", "")
                    raw_data = resp.read(65536) # read first 64KB
                    if "html" in content_type.lower():
                        soup = BeautifulSoup(raw_data, "html.parser")
                        if soup.title and soup.title.string:
                            seen_title = soup.title.string.strip()
                        elif soup.find("h1"):
                            seen_title = soup.find("h1").get_text(strip=True)
                    elif "pdf" in content_type.lower():
                        seen_title = f"[PDF Document: {resp.url}]"
                    else:
                        seen_title = f"[{content_type}: {resp.url}]"
                    print(f"HTTP {status_code} | Seen Title: {seen_title}")
            except Exception as e:
                error_msg = str(e)
                print(f"Error fetching URL: {e}")
        
        results[k] = {
            "key": k,
            "url": url,
            "target_title": title,
            "status_code": status_code,
            "seen_title": seen_title,
            "error": error_msg
        }

with open(REPO_ROOT / "report" / "results" / "manual_refs_check.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nFinished checking manual references.")
