import re
import os
from pathlib import Path

dist_dir = Path("report/dist")
html_path = dist_dir / "report.html"
pdf_path = dist_dir / "report.pdf"

print(f"HTML exists: {html_path.exists()} ({html_path.stat().st_size / 1024:.1f} KB)")
print(f"PDF exists:  {pdf_path.exists()} ({pdf_path.stat().st_size / (1024*1024):.2f} MB)")

# 1. Check Page Count of PDF
pdf_pages = None
try:
    import pypdf
    reader = pypdf.PdfReader(str(pdf_path))
    pdf_pages = len(reader.pages)
except ImportError:
    try:
        import PyPDF2
        reader = PyPDF2.PdfReader(str(pdf_path))
        pdf_pages = len(reader.pages)
    except ImportError:
        # Read from raw pdf trailer /Root /Pages /Count
        content = pdf_path.read_bytes()
        matches = re.findall(rb"/Type\s*/Pages.*?/Count\s+(\d+)", content, re.DOTALL)
        if matches:
            pdf_pages = int(matches[-1])
print(f"PDF Page Count: {pdf_pages}")

# 2. Inspect HTML Content
html = html_path.read_text(encoding="utf-8")

# Check unresolved citations
unresolved_cite_tags = re.findall(r"\{\{cite:[^}]+\}\}", html)
missing_cite_placeholders = re.findall(r"\[\?\]", html)
print(f"Unresolved {{cite:...}} tags: {len(unresolved_cite_tags)}")
print(f"Missing citation tags '[?]': {len(missing_cite_placeholders)}")

# Check KaTeX errors
katex_errors = re.findall(r'class="math-error"|class="katex-error"', html)
print(f"KaTeX math errors: {len(katex_errors)}")

# Check privacy strings
privacy_violations = {
    "wwwsa": len(re.findall(r"wwwsa", html, re.I)),
    "c:\\users": len(re.findall(r"c:\\users", html, re.I)),
    "c:/users": len(re.findall(r"c:/users", html, re.I)),
    "file:///": len(re.findall(r"file:///", html, re.I)),
}
print(f"Privacy violations: {privacy_violations}")

# Check broken internal anchors
# Find all id="..." and name="..."
all_ids = set(re.findall(r'id=["\']([^"\']+)["\']', html))
# Find all href="#..."
internal_links = re.findall(r'href=["\']#([^"\']+)["\']', html)
broken_links = [link for link in internal_links if link not in all_ids]
print(f"Total internal anchor links: {len(internal_links)}")
print(f"Broken internal anchor links: {len(broken_links)}")
if broken_links:
    print(f"Sample broken links: {broken_links[:10]}")

# Check Arabic RTL section
arabic_present = 'class="arabic-section"' in html and 'dir="rtl"' in html
print(f"Arabic RTL section present: {arabic_present}")

# Check tables count
tables_count = len(re.findall(r"<table", html))
print(f"Rendered HTML tables: {tables_count}")

# Check figures / SVGs
svg_count = len(re.findall(r"<svg", html))
mermaid_count = len(re.findall(r'class="mermaid"', html))
print(f"SVGs: {svg_count}, Mermaid diagrams: {mermaid_count}")
