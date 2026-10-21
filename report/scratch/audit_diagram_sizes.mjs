import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const edgeBinaryPath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const htmlPath = path.resolve('report/dist/report.html');

async function run() {
  const browser = await puppeteer.launch({
    executablePath: edgeBinaryPath,
    headless: 'new',
    args: ['--no-sandbox', '--allow-file-access-from-files', '--enable-local-file-accesses']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1754 });
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0', timeout: 60000 });
  await page.waitForFunction(() => window.__READY === true, { timeout: 30000 });

  const diagrams = await page.evaluate(() => {
    const results = [];
    // Find all figure captions and their preceding mermaid or svg containers
    const captions = Array.from(document.querySelectorAll('.figure-caption, div[style*="text-align: center"] b'));
    
    // Also find all .mermaid and svg
    const mermaids = Array.from(document.querySelectorAll('.mermaid, .mermaid-diagram'));
    
    document.querySelectorAll('.mermaid svg, svg').forEach((svg, idx) => {
      // Find caption nearby
      let parent = svg.closest('.mermaid-diagram') || svg.closest('div');
      let captionText = 'Unknown';
      if (parent) {
        let next = parent.nextElementSibling;
        while (next && !captionText.startsWith('Fig')) {
          if (next.classList && next.classList.contains('figure-caption')) {
            captionText = next.textContent.trim();
            break;
          }
          let b = next.querySelector('b');
          if (b && b.textContent.includes('Fig')) {
            captionText = b.textContent.trim();
            break;
          }
          next = next.nextElementSibling;
        }
      }

      const rect = svg.getBoundingClientRect();
      const viewBox = svg.getAttribute('viewBox') || '';
      
      // Get text elements inside svg
      const texts = Array.from(svg.querySelectorAll('text'));
      const fontSizes = texts.map(t => {
        const style = window.getComputedStyle(t);
        return parseFloat(style.fontSize) || 0;
      }).filter(s => s > 0);

      const minFont = fontSizes.length ? Math.min(...fontSizes) : 0;
      const maxFont = fontSizes.length ? Math.max(...fontSizes) : 0;
      const avgFont = fontSizes.length ? (fontSizes.reduce((a,b)=>a+b,0)/fontSizes.length).toFixed(1) : 0;

      // Calculate scale factor: rendered width vs viewBox width
      let vbWidth = rect.width;
      let vbHeight = rect.height;
      if (viewBox) {
        const parts = viewBox.split(/[\s,]+/).map(Number);
        if (parts.length === 4) {
          vbWidth = parts[2];
          vbHeight = parts[3];
        }
      }
      const scaleX = (rect.width / vbWidth).toFixed(2);
      const effectiveMinFont = (minFont * (rect.width / vbWidth)).toFixed(1);

      results.push({
        index: idx + 1,
        caption: captionText.substring(0, 70),
        renderedWidth: Math.round(rect.width),
        renderedHeight: Math.round(rect.height),
        aspectRatio: (rect.width / (rect.height || 1)).toFixed(2),
        viewBox,
        effectiveMinFont,
        avgFont,
        textCount: texts.length
      });
    });

    return results;
  });

  console.log(JSON.stringify(diagrams, null, 2));
  await browser.close();
}

run().catch(console.error);
