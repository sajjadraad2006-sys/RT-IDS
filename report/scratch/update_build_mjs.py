with open('report/build.mjs', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Update Bibliography slot replacement
old_bib_rep = """// Replace references placeholder in text
processedMarkdown = processedMarkdown.replace(
  /<div id="references-section">[\s\S]*?<\/div>/g,
  bibliographyHtml
);"""

new_bib_rep = """// Replace references placeholder in text (at the very end of Chapter 11)
if (processedMarkdown.includes('<!-- BIBLIOGRAPHY_SLOT -->')) {
  processedMarkdown = processedMarkdown.replace('<!-- BIBLIOGRAPHY_SLOT -->', bibliographyHtml);
} else if (processedMarkdown.includes('<div id="references-section">')) {
  processedMarkdown = processedMarkdown.replace(/<div id="references-section">[\s\S]*?<\/div>/g, bibliographyHtml);
} else {
  processedMarkdown += '\\n\\n' + bibliographyHtml;
}"""

assert old_bib_rep in code, 'old_bib_rep not found'
code = code.replace(old_bib_rep, new_bib_rep)

# 2. Update typography and table pagination CSS
old_body_css = """    html, body {
      margin: 0;
      padding: 0;
      background: #ffffff;
      color: #0f172a;
      font-family: "Times New Roman", Times, "Liberation Serif", Georgia, serif;
      font-size: 11pt;
      line-height: 1.65;
      text-rendering: optimizeLegibility;
      -webkit-font-smoothing: antialiased;
    }"""

new_body_css = """    html, body {
      margin: 0;
      padding: 0;
      background: #ffffff;
      color: #0f172a;
      font-family: "Times New Roman", Times, "Liberation Serif", Georgia, serif;
      font-size: 11.5pt;
      line-height: 1.6;
      text-rendering: optimizeLegibility;
      -webkit-font-smoothing: antialiased;
    }"""

assert old_body_css in code, 'old_body_css not found'
code = code.replace(old_body_css, new_body_css)

old_p_css = """    p {
      text-align: justify;
      margin-top: 0;
      margin-bottom: 12px;
      text-indent: 1.8em;
    }"""

new_p_css = """    p {
      text-align: justify;
      text-justify: inter-word;
      margin-top: 0;
      margin-bottom: 12px;
      text-indent: 1.8em;
      orphans: 3;
      widows: 3;
    }"""

assert old_p_css in code, 'old_p_css not found'
code = code.replace(old_p_css, new_p_css)

# 3. Update table container and table CSS
old_table_css = """    .table-container {
      margin: 20px 0;
      page-break-inside: avoid;
      break-inside: avoid;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 9pt;
      line-height: 1.45;
      margin-bottom: 16px;
      page-break-inside: avoid;
      break-inside: avoid;
    }"""

new_table_css = """    .table-container {
      margin: 20px 0;
      width: 100%;
      page-break-inside: auto !important;
      break-inside: auto !important;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 9.5pt;
      line-height: 1.45;
      margin-bottom: 16px;
      page-break-inside: auto !important;
      break-inside: auto !important;
    }

    thead {
      display: table-header-group !important;
    }

    tbody tr {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }"""

assert old_table_css in code, 'old_table_css not found'
code = code.replace(old_table_css, new_table_css)

# 4. Update mermaid diagram CSS
old_mermaid_css = """    /* ── Mermaid Diagrams ────────────────────────────────────────────── */
    .mermaid-diagram {
      text-align: center;
      margin: 20px 0;
      page-break-inside: avoid;
      break-inside: avoid;
    }

    .mermaid {
      display: inline-block;
      text-align: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 9.5pt;
    }"""

new_mermaid_css = """    /* ── Mermaid Diagrams ────────────────────────────────────────────── */
    .mermaid-diagram {
      text-align: center;
      margin: 25px auto;
      page-break-inside: avoid;
      break-inside: avoid;
      width: 100%;
      clear: both;
    }

    .mermaid {
      display: flex !important;
      justify-content: center !important;
      align-items: center !important;
      width: 100% !important;
      margin: 0 auto;
      overflow: visible;
    }

    .mermaid svg {
      display: block !important;
      margin: 0 auto !important;
      width: 100% !important;
      max-width: 720px !important;
      height: auto !important;
      min-height: 220px;
    }"""

assert old_mermaid_css in code, 'old_mermaid_css not found'
code = code.replace(old_mermaid_css, new_mermaid_css)

# 5. Update mermaid.initialize
old_mermaid_init = """          mermaid.initialize({
            startOnLoad: true,
            theme: 'neutral',
            securityLevel: 'loose',
            flowchart: { useMaxWidth: true, htmlLabels: true },
            sequence: { useMaxWidth: true }
          });
          await mermaid.run();"""

new_mermaid_init = """          mermaid.initialize({
            startOnLoad: true,
            theme: 'neutral',
            securityLevel: 'loose',
            flowchart: { useMaxWidth: false, htmlLabels: true, curve: 'basis' },
            sequence: { useMaxWidth: false },
            themeVariables: {
              fontSize: '14px',
              fontFamily: '"Times New Roman", Times, Georgia, serif',
              primaryColor: '#f8fafc',
              primaryBorderColor: '#0284c7',
              lineColor: '#334155'
            }
          });
          await mermaid.run();
          document.querySelectorAll('.mermaid svg').forEach(svg => {
            svg.removeAttribute('style');
            svg.style.width = '100%';
            svg.style.maxWidth = '720px';
            svg.style.height = 'auto';
            svg.style.display = 'block';
            svg.style.margin = '0 auto';
          });"""

assert old_mermaid_init in code, 'old_mermaid_init not found'
code = code.replace(old_mermaid_init, new_mermaid_init)

with open('report/build.mjs', 'w', encoding='utf-8') as f:
    f.write(code)

print('Successfully updated build.mjs with enhanced styles and diagram scaling!')
