import urllib.request
import re
import ssl

ctx = ssl.create_default_context()

def check_arxiv(aid):
    url = f"https://export.arxiv.org/api/query?id_list={aid}"
    req = urllib.request.Request(url, headers={"User-Agent": "CyberGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            txt = r.read().decode("utf-8")
            title_m = re.search(r"<entry>.*?<title>(.*?)</title>", txt, re.DOTALL)
            t = " ".join(title_m.group(1).split()) if title_m else "NOT FOUND"
            print(f"[OK] arXiv {aid} -> {t}")
    except Exception as e:
        print(f"[FAIL] arXiv {aid} -> {e}")

check_arxiv("2305.13860")
check_arxiv("2307.09288")
