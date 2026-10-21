import urllib.request
import urllib.parse
import json

USER_AGENT = "CyberGuardReferenceVerifier/1.0 (mailto:sec-research@university.edu)"

def check_doi(doi):
    url = f"https://api.crossref.org/works/{urllib.parse.quote(doi)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))["message"]
            title = d.get("title", [""])[0] if d.get("title") else ""
            authors = [a.get("family") for a in d.get("author", [])]
            year = d.get("issued", {}).get("date-parts", [[None]])[0][0]
            print(f"[OK] {doi} -> Title: {title} | Authors: {authors} | Year: {year}")
            return d
    except Exception as e:
        print(f"[FAIL] {doi} -> {e}")
        return None

def search_crossref_title(title):
    url = f"https://api.crossref.org/works?query.title={urllib.parse.quote(title)}&rows=3"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            items = json.loads(r.read().decode("utf-8"))["message"]["items"]
            print(f"\n--- Search results for: {title} ---")
            for it in items:
                t = it.get("title", [""])[0] if it.get("title") else ""
                d = it.get("DOI", "")
                authors = [a.get("family") for a in it.get("author", [])]
                y = it.get("issued", {}).get("date-parts", [[None]])[0][0]
                print(f"  DOI: {d} | Year: {y} | Title: {t} | Authors: {authors}")
    except Exception as e:
        print(f"[SEARCH FAIL] {e}")

if __name__ == "__main__":
    print("Testing XGBoost:")
    check_doi("10.1145/2939672.2939785")
    
    print("\nTesting Greshake:")
    search_crossref_title("Not what you've signed up for: Compromising Real-World LLM-Integrated Applications")
    
    print("\nTesting Kaloroumakis D3FEND:")
    search_crossref_title("D3FEND: A Knowledge Graph of Cybersecurity Countermeasures")
    
    print("\nTesting Alshaer:")
    search_crossref_title("Automated security test generation for industrial control systems")
    
    print("\nTesting Genge:")
    search_crossref_title("A cyber-physical testbed for security evaluation of cyber-physical systems")
