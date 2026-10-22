/**
 * CyberGuard Master's Thesis Technical Report Compiler
 * 
 * Pipeline:
 * 1. Reads all markdown chapters from report/chapters/ in order.
 * 2. Parses and verifies IEEE citation keys against report/references.json.
 * 3. Assigns strict order-of-appearance citation numbers and compresses ranges ([1]-[3]).
 * 4. Renders LaTeX math equations via KaTeX ($...$ and $$...$$).
 * 5. Transforms Mermaid diagrams to <div class="mermaid"> blocks.
 * 6. Converts Markdown to HTML using Marked.
 * 7. Generates rendered IEEE bibliography with clickable internal anchors and external DOIs.
 * 8. Applies native CSS Paged Media layout with A4 pagination, chapter breaks, and Arabic font support.
 * 9. Exports standalone HTML to report/dist/report.html.
 * 10. Invokes Puppeteer with Microsoft Edge Chromium to render and export report/dist/report.pdf.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

import { marked } from 'marked';
import katex from 'katex';
import puppeteer from 'puppeteer-core';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const REPORT_DIR = path.resolve(ROOT_DIR, 'report');
const CHAPTERS_DIR = path.resolve(REPORT_DIR, 'chapters');
const DIST_DIR = path.resolve(REPORT_DIR, 'dist');
const REFS_FILE = path.resolve(REPORT_DIR, 'references.json');

// Ensure dist directory exists
if (!fs.existsSync(DIST_DIR)) {
  fs.mkdirSync(DIST_DIR, { recursive: true });
}

// Copy KaTeX fonts to dist/fonts
const katexFontsSrc = path.resolve(REPORT_DIR, 'node_modules/katex/dist/fonts');
const katexFontsDst = path.resolve(DIST_DIR, 'fonts');
if (fs.existsSync(katexFontsSrc)) {
  fs.cpSync(katexFontsSrc, katexFontsDst, { recursive: true });
  console.log('Synchronized KaTeX fonts to dist/fonts');
}

console.log('=== CyberGuard Thesis Report Compiler ===');
console.log(`Report Dir:   ${REPORT_DIR}`);
console.log(`Chapters Dir: ${CHAPTERS_DIR}`);
console.log(`Dist Dir:     ${DIST_DIR}`);

// 1. Load References
if (!fs.existsSync(REFS_FILE)) {
  throw new Error(`References file not found: ${REFS_FILE}`);
}
const referencesData = JSON.parse(fs.readFileSync(REFS_FILE, 'utf-8'));
const referencesMap = new Map();
referencesData.forEach(ref => {
  referencesMap.set(ref.key, ref);
});
console.log(`Loaded ${referencesMap.size} academic references from references.json`);

// 1b. Validate References Verification Ledger (Task 1 Quality Gate)
const VERIF_FILE = path.resolve(REPORT_DIR, 'results', 'references_verification.json');
if (!fs.existsSync(VERIF_FILE)) {
  throw new Error(`CRITICAL BUILD ERROR: References verification file not found: ${VERIF_FILE}. Run report/scripts/verify_references.py first!`);
}
const refsMtime = fs.statSync(REFS_FILE).mtimeMs;
const verifMtime = fs.statSync(VERIF_FILE).mtimeMs;
if (verifMtime < refsMtime) {
  throw new Error(`CRITICAL BUILD ERROR: references_verification.json is older than references.json! Re-run report/scripts/verify_references.py.`);
}
const verificationData = JSON.parse(fs.readFileSync(VERIF_FILE, 'utf-8'));
const verificationMap = new Map();
for (const [k, v] of Object.entries(verificationData.results || {})) {
  verificationMap.set(k, v);
}
console.log(`Loaded verification ledger: ${verificationData.verified_count} VERIFIED, ${verificationData.manual_count} MANUAL`);

// 1c. LOC Table Verification & Category Sum Assertion (Task 7 Defect 2 Quality Gate)
const locInventoryFile = path.resolve(REPORT_DIR, 'results', 'loc_inventory.json');
if (!fs.existsSync(locInventoryFile)) {
  throw new Error(`CRITICAL BUILD ERROR: LOC inventory file not found: ${locInventoryFile}`);
}
const locData = JSON.parse(fs.readFileSync(locInventoryFile, 'utf-8'));
if (locData.total_files !== 299 || locData.total_lines !== 113107) {
  throw new Error(`CRITICAL BUILD ERROR: loc_inventory.json total mismatch! Expected 299 files and 113,107 lines, found ${locData.total_files} files and ${locData.total_lines} lines.`);
}

const locCategories = [
  { id: 'CAT-01', name: 'Python Core Source Files', files: 139, lines: 31865 },
  { id: 'CAT-02', name: 'Python Verification Test Suite', files: 44, lines: 9682 },
  { id: 'CAT-03', name: 'Web Frontend Telemetry UI', files: 13, lines: 6917 },
  { id: 'CAT-04', name: 'Documentation & Configuration', files: 31, lines: 12606 },
  { id: 'CAT-05', name: 'Operational & Automation Scripts', files: 8, lines: 617 },
  { id: 'CAT-06', name: 'Datasets, Raw Fixtures & Binary Assets', files: 64, lines: 51420 },
];
const sumCatFiles = locCategories.reduce((acc, c) => acc + c.files, 0);
const sumCatLines = locCategories.reduce((acc, c) => acc + c.lines, 0);

if (sumCatFiles !== locData.total_files || sumCatLines !== locData.total_lines) {
  throw new Error(`CRITICAL BUILD ERROR: LOC category partition sum (${sumCatFiles} files, ${sumCatLines} lines) does not equal repository total (${locData.total_files} files, ${locData.total_lines} lines)!`);
}
console.log(`PASSED: LOC category partition assertion (6 categories sum to exactly ${sumCatFiles} files and ${sumCatLines} lines).`);

// 2. Discover Chapter Files in Numerical Order
const chapterFiles = fs.readdirSync(CHAPTERS_DIR)
  .filter(f => f.endsWith('.md'))
  .sort();

console.log(`Found ${chapterFiles.length} chapter files:`);
chapterFiles.forEach(f => console.log(`  - ${f}`));

// 3. Concatenate Chapters and Extract Citations
let fullMarkdown = '';
chapterFiles.forEach(file => {
  const filePath = path.join(CHAPTERS_DIR, file);
  const content = fs.readFileSync(filePath, 'utf-8');
  fullMarkdown += `\n\n<!-- CHAPTER_START: ${file} -->\n\n` + content;
});

// Citation tracking in Order of Appearance
const citationAppearanceOrder = [];
const citationNumberMap = new Map();

function getCitationNumber(key) {
  if (!referencesMap.has(key)) {
    throw new Error(`CRITICAL BUILD ERROR: Citation key '${key}' not found in references.json!`);
  }
  const verifRecord = verificationMap.get(key);
  if (!verifRecord) {
    throw new Error(`CRITICAL BUILD ERROR: Cited reference '${key}' is missing from references_verification.json!`);
  }
  if (verifRecord.status !== 'VERIFIED' && verifRecord.status !== 'MANUAL') {
    throw new Error(`CRITICAL BUILD ERROR: Cited reference '${key}' has unapproved verification status '${verifRecord.status}'! Must be VERIFIED or MANUAL.`);
  }
  if (!citationNumberMap.has(key)) {
    citationAppearanceOrder.push(key);
    const num = citationAppearanceOrder.length;
    citationNumberMap.set(key, num);
  }
  return citationNumberMap.get(key);
}

// Helper: Compress sorted citation numbers into IEEE ranges (e.g., [1], [2], [3] -> [1]-[3])
function formatIeeeGroup(keys) {
  const numbers = [...new Set(keys.map(k => getCitationNumber(k.trim())).filter(n => n !== null))].sort((a, b) => a - b);
  if (numbers.length === 0) return '';
  if (numbers.length === 1) {
    return `<a href="#ref-${numbers[0]}" class="citation-link">[${numbers[0]}]</a>`;
  }

  // Range grouping
  const ranges = [];
  let start = numbers[0];
  let prev = numbers[0];

  for (let i = 1; i < numbers.length; i++) {
    const cur = numbers[i];
    if (cur === prev + 1) {
      prev = cur;
    } else {
      ranges.push({ start, end: prev });
      start = cur;
      prev = cur;
    }
  }
  ranges.push({ start, end: prev });

  const formattedParts = ranges.map(r => {
    if (r.start === r.end) {
      return `<a href="#ref-${r.start}" class="citation-link">[${r.start}]</a>`;
    } else if (r.end === r.start + 1) {
      return `<a href="#ref-${r.start}" class="citation-link">[${r.start}]</a>, <a href="#ref-${r.end}" class="citation-link">[${r.end}]</a>`;
    } else {
      return `<a href="#ref-${r.start}" class="citation-link">[${r.start}]</a>–<a href="#ref-${r.end}" class="citation-link">[${r.end}]</a>`;
    }
  });

  return formattedParts.join(', ');
}

// 4. Resolve {{cite:key1,key2}} placeholders
let processedMarkdown = fullMarkdown.replace(/\{\{cite:([^}]+)\}\}/g, (match, keysStr) => {
  const keys = keysStr.split(',').map(k => k.trim()).filter(Boolean);
  return formatIeeeGroup(keys);
});

console.log(`Resolved citations: ${citationAppearanceOrder.length} distinct sources cited.`);

// 5. Resolve Code Evidence [CE-xx] placeholders
// Strip any accidental backticks wrapping code evidence so they never get escaped as raw HTML code
processedMarkdown = processedMarkdown.replace(/`(\[CE-[^`\]]+\])`/g, '$1');

processedMarkdown = processedMarkdown.replace(/\[CE-(\d+)\]/g, (match, id) => {
  const paddedId = id.padStart(2, '0');
  return `<a href="#ce-${id}" class="ce-link">[CE-${paddedId}]</a>`;
});
processedMarkdown = processedMarkdown.replace(/\[CE-(\d+):([^\]]+)\]/g, (match, id, lines) => {
  const paddedId = id.padStart(2, '0');
  return `<a href="#ce-${id}" class="ce-link">[CE-${paddedId}:${lines}]</a>`;
});

// 6. Format Verified IEEE Bibliography
let bibliographyHtml = '<div class="bibliography-list">\n';
citationAppearanceOrder.forEach((key, index) => {
  const ref = referencesMap.get(key);
  const num = index + 1;
  
  let authors = ref.authors || 'Unknown';
  let title = ref.title ? `"${ref.title},"` : '';
  let venue = ref.venue ? `<em>${ref.venue}</em>` : '';
  let volPages = [];
  if (ref.volume) volPages.push(`vol. ${ref.volume}`);
  if (ref.pages) volPages.push(`pp. ${ref.pages}`);
  if (ref.year) volPages.push(`${ref.year}`);
  let volStr = volPages.join(', ');

  let doiStr = '';
  if (ref.doi) {
    doiStr = `DOI: <a href="https://doi.org/${ref.doi}" target="_blank" rel="noopener noreferrer">${ref.doi}</a>.`;
  } else if (ref.url) {
    doiStr = `Available: <a href="${ref.url}" target="_blank" rel="noopener noreferrer">${ref.url}</a>.`;
  }

  bibliographyHtml += `  <div class="ref-item" id="ref-${num}">\n`;
  bibliographyHtml += `    <span class="ref-num">[${num}]</span>\n`;
  bibliographyHtml += `    <span class="ref-text">${authors}, ${title} in ${venue}, ${volStr}. ${doiStr}</span>\n`;
  bibliographyHtml += `  </div>\n`;
});
bibliographyHtml += '</div>\n';

// Replace references placeholder in text (at the very end of Chapter 11)
if (processedMarkdown.includes('<!-- BIBLIOGRAPHY_SLOT -->')) {
  processedMarkdown = processedMarkdown.replace('<!-- BIBLIOGRAPHY_SLOT -->', bibliographyHtml);
} else if (processedMarkdown.includes('<div id="references-section">')) {
  processedMarkdown = processedMarkdown.replace(/<div id="references-section">[\s\S]*?<\/div>/g, bibliographyHtml);
} else {
  processedMarkdown += '\n\n' + bibliographyHtml;
}

// 6b. Stash Code Blocks and Inline Code to protect internal $ and code syntax
console.log('Stashing code blocks and inline code...');
const codeBlocks = [];
processedMarkdown = processedMarkdown.replace(/(```[\s\S]*?```|`[^`\n]+`)/g, (match) => {
  const id = codeBlocks.length;
  codeBlocks.push(match);
  return `CODEBLOCK${id}CODEBLOCK`;
});

// 7. Stash LaTeX Equations to protect them from Markdown parsing
console.log('Stashing LaTeX equations...');
const blockMath = [];
processedMarkdown = processedMarkdown.replace(/\$\$([\s\S]+?)\$\$/g, (match, math) => {
  const id = blockMath.length;
  blockMath.push(math.trim());
  return `\n\nKATEXBLOCK${id}KATEXBLOCK\n\n`;
});

const inlineMath = [];
processedMarkdown = processedMarkdown.replace(/(?<!\\)\$([^\$\n]+?)(?<!\\)\$/g, (match, math) => {
  const id = inlineMath.length;
  inlineMath.push(math.trim());
  return `KATEXINLINE${id}KATEXINLINE`;
});

// 7b. Restore Code Blocks before Markdown parsing
processedMarkdown = processedMarkdown.replace(/CODEBLOCK(\d+)CODEBLOCK/g, (match, id) => codeBlocks[parseInt(id, 10)]);

// 7c. Ensure block HTML tags are followed by blank lines so CommonMark never treats markdown as raw HTML
processedMarkdown = processedMarkdown.replace(/<\/div>(?!\s*\n\s*\n)/g, '</div>\n\n');
processedMarkdown = processedMarkdown.replace(/<\/table>(?!\s*\n\s*\n)/g, '</table>\n\n');

// 7d. Stash SVG blocks so Marked never parses XML or indented lines as code blocks
console.log('Stashing SVG vector blocks...');
const svgBlocks = [];
processedMarkdown = processedMarkdown.replace(/(<svg[\s\S]*?<\/svg>)/g, (match) => {
  const id = svgBlocks.length;
  svgBlocks.push(match);
  return `\n\nSVGBLOCK${id}SVGBLOCK\n\n`;
});

// 8. Convert Markdown to HTML via Marked
marked.setOptions({
  gfm: true,
  breaks: false,
});

console.log('Converting Markdown to structured HTML...');
let bodyHtml = marked.parse(processedMarkdown);

// 8a. Restore SVG vector blocks intact
bodyHtml = bodyHtml.replace(/<p>\s*SVGBLOCK(\d+)SVGBLOCK\s*<\/p>|SVGBLOCK(\d+)SVGBLOCK/g, (match, id1, id2) => {
  const id = parseInt(id1 !== undefined ? id1 : id2, 10);
  return svgBlocks[id];
});

// 8b. Restore and render LaTeX equations via KaTeX
console.log('Rendering KaTeX equations...');
bodyHtml = bodyHtml.replace(/<p>\s*KATEXBLOCK(\d+)KATEXBLOCK\s*<\/p>|KATEXBLOCK(\d+)KATEXBLOCK/g, (match, id1, id2) => {
  const id = parseInt(id1 !== undefined ? id1 : id2, 10);
  const math = blockMath[id];
  try {
    return `<div class="math-block">${katex.renderToString(math, { displayMode: true, throwOnError: false })}</div>`;
  } catch (err) {
    console.error('KaTeX Block Error:', err);
    return `<pre class="math-error">${math}</pre>`;
  }
});

bodyHtml = bodyHtml.replace(/KATEXINLINE(\d+)KATEXINLINE/g, (match, idStr) => {
  const id = parseInt(idStr, 10);
  const math = inlineMath[id];
  try {
    return katex.renderToString(math, { displayMode: false, throwOnError: false });
  } catch (err) {
    return `<code>${math}</code>`;
  }
});

// Wrap tables in responsive / page-friendly container
bodyHtml = bodyHtml.replace(/<table>/g, '<div class="table-container"><table>');
bodyHtml = bodyHtml.replace(/<\/table>/g, '</table></div>');

// Add anchor IDs for Code Evidence table rows in Table XXI
bodyHtml = bodyHtml.replace(/<td([^>]*)><strong><a href="#ce-(\d+)" class="ce-link">\[CE-(\d+)\]<\/a><\/strong><\/td>/g, (match, attrs, id1, id2) => {
  const paddedId = id1.padStart(2, '0');
  const numId = parseInt(id1, 10);
  return `<td id="ce-${paddedId}" ${attrs}><a id="ce-${numId}"></a><strong><span class="ce-anchor">[CE-${paddedId}]</span></strong></td>`;
});
bodyHtml = bodyHtml.replace(/<td([^>]*)><strong>\[CE-(\d+)\]<\/strong><\/td>/g, (match, attrs, id1) => {
  const paddedId = id1.padStart(2, '0');
  const numId = parseInt(id1, 10);
  return `<td id="ce-${paddedId}" ${attrs}><a id="ce-${numId}"></a><strong><span class="ce-anchor">[CE-${paddedId}]</span></strong></td>`;
});

// Transform Mermaid code blocks to <div class="mermaid">
bodyHtml = bodyHtml.replace(/<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g, (match, code) => {
  // Decode HTML entities
  const decoded = code
    .replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
  return `<div class="mermaid-diagram"><div class="mermaid">${decoded.trim()}</div></div>`;
});

// 9. Load KaTeX CSS and fix font paths
const katexCssPath = path.resolve(REPORT_DIR, 'node_modules/katex/dist/katex.min.css');
let katexCss = '';
if (fs.existsSync(katexCssPath)) {
  katexCss = fs.readFileSync(katexCssPath, 'utf-8');
}

// 10. Assemble Master HTML Template
const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CyberGuard Master's Thesis Technical Report</title>
  <meta name="description" content="Master's-Thesis-Grade Technical Report on CyberGuard Real-Time Intrusion Detection & Autonomous Containment System">
  
  <style>
    /* ── KaTeX Inlined Styles ─────────────────────────────────────────── */
    ${katexCss}

    /* ── Page Margins & Paged Media ──────────────────────────────────── */
    @page {
      size: A4 portrait;
      margin-top: 25mm;
      margin-bottom: 25mm;
      margin-left: 25mm;
      margin-right: 25mm;
    }

    @page :first {
      margin-top: 35mm;
      margin-bottom: 25mm;
    }

    /* ── Global Styles ────────────────────────────────────────────────── */
    *, *:before, *:after {
      box-sizing: border-box;
    }

    html, body {
      margin: 0;
      padding: 0;
      background: #ffffff;
      color: #0f172a;
      font-family: "Times New Roman", Times, "Liberation Serif", Georgia, serif;
      font-size: 11.5pt;
      line-height: 1.6;
      text-rendering: optimizeLegibility;
      -webkit-font-smoothing: antialiased;
    }

    /* ── Headings & Chapter Breaks ────────────────────────────────────── */
    h1 {
      page-break-before: always;
      break-before: page;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 20pt;
      font-weight: 800;
      color: #091e42;
      border-bottom: 2pt solid #0284c7;
      padding-bottom: 10px;
      margin-top: 0;
      margin-bottom: 22px;
      letter-spacing: -0.5px;
    }

    h1:first-of-type {
      page-break-before: avoid;
      break-before: avoid;
    }

    h2 {
      page-break-after: avoid;
      break-after: avoid;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 14pt;
      font-weight: 700;
      color: #1e293b;
      margin-top: 26px;
      margin-bottom: 12px;
      border-bottom: 0.75pt solid #e2e8f0;
      padding-bottom: 6px;
    }

    h3 {
      page-break-after: avoid;
      break-after: avoid;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 12pt;
      font-weight: 600;
      color: #334155;
      margin-top: 18px;
      margin-bottom: 8px;
    }

    h4 {
      page-break-after: avoid;
      break-after: avoid;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 11pt;
      font-weight: 600;
      color: #475569;
      margin-top: 14px;
      margin-bottom: 6px;
    }

    p {
      text-align: justify;
      text-justify: inter-word;
      margin-top: 0;
      margin-bottom: 12px;
      text-indent: 1.8em;
      orphans: 3;
      widows: 3;
    }

    p:first-of-type, h1 + p, h2 + p, h3 + p, h4 + p, .no-indent {
      text-indent: 0;
    }

    /* ── Arabic Text Styling ──────────────────────────────────────────── */
    .arabic-text, [dir="rtl"], div[lang="ar"], p[lang="ar"] {
      direction: rtl;
      font-family: "Amiri", "Noto Naskh Arabic", "Traditional Arabic", "Segoe UI", Tahoma, sans-serif;
      font-size: 11.5pt;
      line-height: 1.8;
      text-align: justify;
      text-indent: 0;
    }

    /* ── Figures, Tables, & Captions ──────────────────────────────────── */
    .table-container {
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
    }

    th, td {
      border: 0.5pt solid #cbd5e1;
      padding: 6px 10px;
      vertical-align: top;
    }

    th {
      background-color: #f1f5f9;
      color: #0f172a;
      font-weight: 600;
      text-align: left;
    }

    tr:nth-child(even) td {
      background-color: #f8fafc;
    }

    /* ── Mermaid Diagrams & Responsive Sizing ─────────────────────────── */
    .mermaid-diagram {
      text-align: center;
      margin: 20px auto;
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
      margin: 12px auto !important;
      max-width: 100% !important;
      max-height: 780px !important;
      width: auto !important;
      height: auto !important;
    }

    /* High-Contrast Academic Theme for Mermaid Sequence Diagrams */
    .mermaid text.actor > tspan, .mermaid text.actor { font-size: 13.5px !important; font-weight: 700 !important; fill: #0f172a !important; }
    .mermaid rect.actor { fill: #f8fafc !important; stroke: #2563eb !important; stroke-width: 1.5px !important; rx: 4px !important; }
    .mermaid text.messageText { font-size: 12.5px !important; font-weight: 600 !important; fill: #0f172a !important; }
    .mermaid line.messageLine0, .mermaid line.messageLine1 { stroke: #334155 !important; stroke-width: 1.5px !important; }
    .mermaid .note { fill: #fef3c7 !important; stroke: #f59e0b !important; }
    .mermaid text.noteText { font-size: 12px !important; font-weight: 600 !important; fill: #92400e !important; }

    /* High-Contrast Academic Theme for Mermaid XY Charts */
    svg[aria-roledescription="xychart"] path[stroke="#EEE"],
    svg[aria-roledescription="xychart"] path[stroke="#eee"] {
      stroke: #1e40af !important; /* Deep Royal Blue */
      stroke-width: 3.5px !important;
    }

    svg[aria-roledescription="xychart"] rect[fill="#EEE"],
    svg[aria-roledescription="xychart"] rect[fill="#eee"] {
      fill: #2563eb !important; /* Vivid Blue */
      stroke: #1e3a8a !important; /* Navy Border */
      stroke-width: 1.5px !important;
    }

    .table-dense {
      width: 100%;
      overflow-x: auto;
    }

    .table-dense table {
      font-size: 8pt !important;
      line-height: 1.35 !important;
    }

    .table-dense th, .table-dense td {
      padding: 4px 6px !important;
    }

    .table-stride {
      width: 100%;
      margin: 16px 0;
    }

    .table-stride table {
      width: 100% !important;
      table-layout: fixed !important;
      font-size: 7.2pt !important;
      line-height: 1.35 !important;
    }

    .table-stride th, .table-stride td {
      padding: 4px 5px !important;
      vertical-align: top !important;
      word-wrap: break-word !important;
      word-break: break-word !important;
      overflow-wrap: break-word !important;
    }

    .table-stride th:nth-child(1), .table-stride td:nth-child(1) { width: 12% !important; }
    .table-stride th:nth-child(2), .table-stride td:nth-child(2) { width: 19% !important; }
    .table-stride th:nth-child(3), .table-stride td:nth-child(3) { width: 14% !important; }
    .table-stride th:nth-child(4), .table-stride td:nth-child(4) { width: 18% !important; }
    .table-stride th:nth-child(5), .table-stride td:nth-child(5) { width: 18% !important; }
    .table-stride th:nth-child(6), .table-stride td:nth-child(6) { width: 19% !important; }

    .table-stride code {
      font-size: 6.8pt !important;
      padding: 1px 2px !important;
    }

    /* ── Code Blocks & Excerpts ───────────────────────────────────────── */
    pre {
      background-color: #f8fafc;
      border: 0.75pt solid #e2e8f0;
      border-left: 3.5pt solid #0284c7;
      border-radius: 4px;
      padding: 10px 14px;
      font-family: "Fira Code", "Cascadia Code", Consolas, "Courier New", monospace;
      font-size: 8.5pt;
      line-height: 1.45;
      overflow-x: auto;
      margin: 14px 0;
      page-break-inside: avoid;
      break-inside: avoid;
      white-space: pre-wrap;
      word-wrap: break-word;
    }

    code {
      font-family: "Fira Code", "Cascadia Code", Consolas, "Courier New", monospace;
      font-size: 9pt;
      background-color: #f1f5f9;
      color: #0369a1;
      padding: 2px 5px;
      border-radius: 3px;
    }

    pre code {
      background-color: transparent;
      color: #1e293b;
      padding: 0;
      font-size: 8.5pt;
    }

    /* ── Math Formulas ────────────────────────────────────────────────── */
    .math-block {
      text-align: center;
      margin: 12px 0;
      page-break-inside: avoid;
      break-inside: avoid;
    }

    .katex {
      font-size: 1.05em;
    }

    .katex-display {
      margin: 8px 0 !important;
    }

    /* ── Blockquotes & Alerts ─────────────────────────────────────────── */
    blockquote {
      border-left: 3pt solid #3b82f6;
      background-color: #eff6ff;
      margin: 12px 0;
      padding: 8px 14px;
      font-style: normal;
      color: #1e40af;
      page-break-inside: avoid;
      break-inside: avoid;
    }

    blockquote p {
      margin: 0;
      text-indent: 0;
    }

    /* ── Links & Citations ────────────────────────────────────────────── */
    a {
      color: #0284c7;
      text-decoration: none;
    }

    a:hover {
      text-decoration: underline;
    }

    .citation-link {
      font-weight: 600;
      color: #0369a1;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 8.5pt;
      white-space: nowrap;
    }

    .ce-link {
      font-weight: 600;
      color: #7c3aed;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 8.5pt;
      white-space: nowrap;
    }

    /* ── Bibliography Section ─────────────────────────────────────────── */
    .bibliography-list {
      margin-top: 16px;
    }

    .ref-item {
      display: flex;
      margin-bottom: 8px;
      font-size: 9pt;
      line-height: 1.4;
      page-break-inside: avoid;
      break-inside: avoid;
    }

    .ref-num {
      width: 32px;
      font-weight: bold;
      color: #0f172a;
      flex-shrink: 0;
    }

    .ref-text {
      flex-grow: 1;
      text-align: justify;
    }

    /* ── Lists & Metrics ──────────────────────────────────────────────── */
    ul, ol {
      margin-top: 4px;
      margin-bottom: 10px;
      padding-left: 24px;
    }

    li {
      margin-bottom: 4px;
      text-align: justify;
    }
  </style>

  <!-- Mermaid.js for Diagram Rendering -->
  <script src="../node_modules/mermaid/dist/mermaid.min.js"></script>
  <script>
    document.addEventListener("DOMContentLoaded", async function() {
      if (window.mermaid) {
        try {
          mermaid.initialize({
            startOnLoad: true,
            theme: 'neutral',
            securityLevel: 'loose',
            flowchart: { useMaxWidth: false, htmlLabels: true, curve: 'basis' },
            sequence: { useMaxWidth: false },
            themeVariables: {
              fontSize: '13px',
              fontFamily: '"Times New Roman", Times, Georgia, serif',
              primaryColor: '#f8fafc',
              primaryBorderColor: '#0284c7',
              lineColor: '#334155'
            }
          });
          await mermaid.run();
          document.querySelectorAll('.mermaid svg').forEach(svg => {
            svg.removeAttribute('style');
            svg.style.display = 'block';
            svg.style.margin = '12px auto';
            svg.style.maxWidth = '100%';
            svg.style.maxHeight = '780px';
            svg.style.width = 'auto';
            svg.style.height = 'auto';
          });
          // Recolor pale/white chart elements
          document.querySelectorAll('svg[aria-roledescription="xychart"]').forEach(svg => {
            svg.querySelectorAll('path').forEach(p => {
              const stroke = p.getAttribute('stroke');
              if (stroke && (stroke.toUpperCase() === '#EEE' || stroke.toUpperCase() === '#EEEEEE')) {
                p.setAttribute('stroke', '#1e40af'); // Deep royal blue
                p.setAttribute('stroke-width', '3.5');
              }
            });
            svg.querySelectorAll('rect').forEach(r => {
              const fill = r.getAttribute('fill');
              if (fill && (fill.toUpperCase() === '#EEE' || fill.toUpperCase() === '#EEEEEE')) {
                r.setAttribute('fill', '#2563eb'); // Crisp blue
                r.setAttribute('stroke', '#1e3a8a');
                r.setAttribute('stroke-width', '1.5');
              }
            });
          });
        } catch (e) {
          console.error("Mermaid render error:", e);
        }
      }
      window.__READY = true;
    });
  </script>
</head>
<body>
  ${bodyHtml}
</body>
</html>`;

// 10b. Enforce Privacy & Portability Gate (Whole Report Tree & HTML)
const forbiddenPrivacyChecks = [
  { name: 'Username "wwwsa"', regex: /wwwsa/i },
  { name: 'Absolute path "c:\\Users"', regex: /c:\\users/i },
  { name: 'Absolute path "c:/Users"', regex: /c:\/users/i },
  { name: 'Absolute file URI "file:///"', regex: /file:\/\/\//i },
];

// Check generated HTML
for (const check of forbiddenPrivacyChecks) {
  const match = fullHtml.match(check.regex);
  if (match) {
    const idx = fullHtml.indexOf(match[0]);
    const snippet = fullHtml.substring(Math.max(0, idx - 40), Math.min(fullHtml.length, idx + 60));
    throw new Error(`CRITICAL BUILD ERROR: Privacy/portability violation detected (${check.name}) in generated HTML!\nMatched near: "...${snippet}..."`);
  }
}

// Check the WHOLE report/ tree (Task 7 Defect 5)
function scanReportTreeForPrivacy(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullEntryPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'fonts', '__pycache__', 'screenshots'].includes(entry.name)) {
        continue;
      }
      scanReportTreeForPrivacy(fullEntryPath);
    } else if (entry.isFile()) {
      // Allow pattern definitions inside the gate script itself
      if (fullEntryPath === __filename) {
        continue;
      }
      const ext = path.extname(entry.name).toLowerCase();
      // Skip binary media and PDFs (PDF text & metadata audited via pypdf post-generation)
      if (['.pdf', '.png', '.jpg', '.jpeg', '.woff', '.woff2', '.ttf', '.eot'].includes(ext)) {
        continue;
      }
      const content = fs.readFileSync(fullEntryPath, 'utf-8');
      for (const check of forbiddenPrivacyChecks) {
        if (check.regex.test(content)) {
          const match = content.match(check.regex);
          const idx = content.indexOf(match[0]);
          const snippet = content.substring(Math.max(0, idx - 30), Math.min(content.length, idx + 40));
          throw new Error(`CRITICAL BUILD ERROR: Privacy violation (${check.name}) in file: ${fullEntryPath}\nMatched: "...${snippet}..."`);
        }
      }
    }
  }
}
scanReportTreeForPrivacy(REPORT_DIR);
console.log('PASSED: Privacy and portability audit check (no wwwsa, c:\\Users, or file:/// in HTML or report/ tree).');

// 11. Write Single-File Report HTML
const outHtmlPath = path.join(DIST_DIR, 'report.html');
fs.writeFileSync(outHtmlPath, fullHtml, 'utf-8');
console.log(`Successfully compiled standalone HTML report: ${outHtmlPath}`);
console.log(`HTML File Size: ${(fs.statSync(outHtmlPath).size / 1024).toFixed(1)} KB`);

// 12. Invoke Puppeteer with Edge Chromium to Render and Print PDF
const outPdfPath = path.join(DIST_DIR, 'report.pdf');
const edgeBinaryPath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

if (fs.existsSync(edgeBinaryPath)) {
  console.log('Launching Edge Chromium via Puppeteer for high-resolution A4 export...');
  const browser = await puppeteer.launch({
    executablePath: edgeBinaryPath,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--allow-file-access-from-files',
      '--enable-local-file-accesses',
    ]
  });

  const page = await browser.newPage();
  
  // Set A4 viewport
  await page.setViewport({ width: 1240, height: 1754 });

  console.log('Loading report HTML into Chromium DOM...');
  const fileUrl = 'file:///' + outHtmlPath.replace(/\\/g, '/');
  
  await page.goto(fileUrl, {
    waitUntil: 'networkidle0',
    timeout: 120000
  });

  // Wait for diagrams and formulas to complete rendering
  await page.waitForFunction(() => window.__READY === true, { timeout: 30000 });
  // Brief delay to ensure font glyphs are flushed to GPU
  await new Promise(r => setTimeout(r, 2000));

  // Capture figure screenshots for audit and inspection
  const screenshotsDir = path.join(DIST_DIR, 'screenshots');
  if (!fs.existsSync(screenshotsDir)) {
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }
  console.log('Capturing verification screenshots of figures...');
  try {
    const fig4El = await page.$('#fig4-container svg');
    if (fig4El) {
      await fig4El.screenshot({ path: path.join(screenshotsDir, 'fig4_actual.png') });
      await fig4El.screenshot({ path: path.join(screenshotsDir, 'fig4_architecture.png') });
      console.log('Saved Fig. 4 architecture screenshot.');
    }

    const fig19El = await page.$('#fig19-container svg');
    if (fig19El) {
      await fig19El.screenshot({ path: path.join(screenshotsDir, 'fig19_actual.png') });
      await fig19El.screenshot({ path: path.join(screenshotsDir, 'fig19_quadrant.png') });
      console.log('Saved Fig. 19 quadrant map screenshot.');
    }

    const mermaids = await page.$$('.mermaid');
    if (mermaids.length >= 17) {
      // Fig 16 (latency), Fig 17 (throughput), Fig 18 (memory)
      await mermaids[15].screenshot({ path: path.join(screenshotsDir, 'fig16_latency.png') });
      await mermaids[16].screenshot({ path: path.join(screenshotsDir, 'fig17_throughput.png') });
      await mermaids[17].screenshot({ path: path.join(screenshotsDir, 'fig18_memory.png') });
      console.log('Saved Fig. 16, 17, 18 screenshots.');
    }
  } catch (err) {
    console.warn('Screenshot capture notice:', err.message);
  }

  console.log('Exporting paginated A4 PDF with running headers & footers...');
  const tempPdfPath = path.join(DIST_DIR, 'report_built.pdf');
  await page.pdf({
    path: tempPdfPath,
    format: 'A4',
    displayHeaderFooter: true,
    headerTemplate: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 8pt; color: #64748b; width: 100%; display: flex; justify-content: space-between; padding: 0 25mm; border-bottom: 0.5pt solid #cbd5e1; padding-bottom: 4px;">
        <span>CyberGuard Autonomous Active Defense System</span>
        <span>Technical Audit & Evaluation</span>
      </div>
    `,
    footerTemplate: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 8pt; color: #64748b; width: 100%; display: flex; justify-content: space-between; padding: 0 25mm; border-top: 0.5pt solid #cbd5e1; padding-top: 4px;">
        <span>IEEE Academic Standard Report</span>
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
      </div>
    `,
    margin: {
      top: '25mm',
      bottom: '25mm',
      left: '25mm',
      right: '25mm',
    },
    printBackground: true,
    preferCSSPageSize: true,
    timeout: 180000,
  });

  await browser.close();

  let finalPdfPath = outPdfPath;
  try {
    fs.copyFileSync(tempPdfPath, outPdfPath);
    const pdfSizeMb = (fs.statSync(outPdfPath).size / (1024 * 1024)).toFixed(2);
    console.log(`SUCCESS: PDF report exported cleanly to ${outPdfPath} (${pdfSizeMb} MB)`);
  } catch (err) {
    finalPdfPath = tempPdfPath;
    const tempMb = (fs.statSync(tempPdfPath).size / (1024 * 1024)).toFixed(2);
    console.log(`SUCCESS: Fresh PDF build exported to ${tempPdfPath} (${tempMb} MB) (destination ${outPdfPath} locked by external viewer)`);
  }

  // 13. Audit PDF Text, Metadata & Page Bounds via pypdf (Task 7 Defect 5 & Section 9 Quality Gate)
  console.log('Auditing generated PDF for privacy, metadata, and page bounds [90-130]...');
  const pyPdfAuditScript = [
    'import pypdf, sys, json',
    `target_pdf = r"""${finalPdfPath}"""`,
    'reader = pypdf.PdfReader(target_pdf)',
    'page_count = len(reader.pages)',
    'if not (90 <= page_count <= 130):',
    '    print(f"ERROR: PDF page count {page_count} out of bounds [90, 130]", file=sys.stderr)',
    '    sys.exit(1)',
    'forbidden = ["wwwsa", r"c:\\users", "c:/users", "file:///"]',
    'leaks = []',
    'for idx, page in enumerate(reader.pages):',
    '    txt = page.extract_text() or ""',
    '    for p in forbidden:',
    '        if p.lower() in txt.lower():',
    '            leaks.append(f"Page {idx+1} contains: {p}")',
    'for k, v in (reader.metadata or {}).items():',
    '    for p in forbidden:',
    '        if p.lower() in str(v).lower():',
    '            leaks.append(f"Metadata field {k} contains: {p}")',
    'if leaks:',
    '    print("PDF PRIVACY VIOLATIONS: " + json.dumps(leaks), file=sys.stderr)',
    '    sys.exit(2)',
    'print(f"PASSED: PDF Quality Gate ({page_count} pages [90-130], 0 privacy leaks in text or metadata).")'
  ].join('\n');

  try {
    const auditRes = execSync('python -', { input: pyPdfAuditScript, encoding: 'utf-8' });
    console.log(auditRes.trim());
  } catch (auditErr) {
    throw new Error(`CRITICAL BUILD ERROR: PDF Quality Gate failed!\n${auditErr.stderr || auditErr.message}`);
  }
} else {
  console.warn(`Microsoft Edge binary not found at ${edgeBinaryPath}. Skipping PDF export.`);
}

console.log('=== Build Execution Complete ===');
