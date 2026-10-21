with open('report/chapters/11-references-and-appendices.md', 'r', encoding='utf-8') as f:
    text = f.read()

bib_slot_header = """## Verified Academic and Standards Bibliography

The complete, verified academic bibliography is compiled directly from `report/references.json` and rendered in strict accordance with the IEEE Citation Style. Every listed citation has been verified against official digital object identifiers (DOIs) or authoritative standards registries.

<!-- BIBLIOGRAPHY_SLOT -->

---"""

# Remove from top
text = text.replace(bib_slot_header, "")

# Append to very bottom
bib_at_end = """

---

<div class="page-break"></div>

## REFERENCES: Verified Academic and Standards Bibliography

The complete, verified academic bibliography is compiled directly from `report/references.json` and rendered in strict accordance with the IEEE Citation Style. Every listed citation has been verified against official digital object identifiers (DOIs) or authoritative standards registries. Each cited source is cross-linked bidirectionally to its appearances within the dissertation.

<!-- BIBLIOGRAPHY_SLOT -->
"""

text = text.rstrip() + bib_at_end

with open('report/chapters/11-references-and-appendices.md', 'w', encoding='utf-8') as f:
    f.write(text)

print('Moved bibliography to the very end of Chapter 11!')
