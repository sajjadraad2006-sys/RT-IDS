import os
import re

REPORT_DIR = "report"

# Patterns to replace
REPLACEMENTS = [
    # file:///c:/Users/wwwsa/OneDrive/Desktop/sec/PATH
    (re.compile(r"file:///[cC]:/[uU]sers/[wW][wW][wW][sS][aA]/OneDrive/Desktop/sec/"), ""),
    # file:///c:/Users/wwwsa/OneDrive/Desktop/sec
    (re.compile(r"file:///[cC]:/[uU]sers/[wW][wW][wW][sS][aA]/OneDrive/Desktop/sec"), "."),
    # c:\Users\wwwsa\OneDrive\Desktop\sec\
    (re.compile(r"[cC]:\\[uU]sers\\[wW][wW][wW][sS][aA]\\OneDrive\\Desktop\\sec\\"), ""),
    # c:\Users\wwwsa\OneDrive\Desktop\sec
    (re.compile(r"[cC]:\\[uU]sers\\[wW][wW][wW][sS][aA]\\OneDrive\\Desktop\\sec"), "."),
    # c:/Users/wwwsa/OneDrive/Desktop/sec/
    (re.compile(r"[cC]:/[uU]sers/[wW][wW][wW][sS][aA]/OneDrive/Desktop/sec/"), ""),
    # c:/Users/wwwsa/OneDrive/Desktop/sec
    (re.compile(r"[cC]:/[uU]sers/[wW][wW][wW][sS][aA]/OneDrive/Desktop/sec"), "."),
    # C:\Users\wwwsa\AppData\Local\...
    (re.compile(r"[cC]:\\[uU]sers\\[wW][wW][wW][sS][aA]\\[^\s'\"`]+"), "."),
]

def scrub_file(filepath):
    # Skip binary, git, node_modules, dist
    if any(k in filepath for k in ["node_modules", ".git", "dist", "pdf"]):
        return 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return 0

    original = content
    # In chapters and ledgers, also fix any stray file:/// links
    # Convert [text](file:///...) to [text](...)
    content = re.sub(r"file:///[a-zA-Z]:/[^\s\)\"']+/sec/", "", content)
    
    # Specific fix for PROGRESS.md workspace line
    content = content.replace("c:\\Users\\wwwsa\\OneDrive\\Desktop\\sec", ".")
    content = content.replace("c:/Users/wwwsa/OneDrive/Desktop/sec", ".")

    for pattern, repl in REPLACEMENTS:
        content = pattern.sub(repl, content)

    # Clean any remaining username occurrences
    content = content.replace("wwwsa", "developer")

    if content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return 1
    return 0

total_modified = 0
for root, dirs, files in os.walk(REPORT_DIR):
    if any(k in root for k in ["node_modules", ".git", "dist"]):
        continue
    for file in files:
        if file.endswith((".md", ".json", ".py", ".mjs", ".txt", ".js")):
            fp = os.path.join(root, file)
            # Don't touch check_dois or scrub_privacy itself
            if "scrub_privacy.py" in fp:
                continue
            if scrub_file(fp):
                print(f"[SCRUBBED] {fp}")
                total_modified += 1

print(f"\nTotal files scrubbed: {total_modified}")
