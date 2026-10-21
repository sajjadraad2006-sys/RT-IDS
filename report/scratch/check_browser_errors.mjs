import puppeteer from 'puppeteer-core';
import path from 'path';

const edgeBinaryPath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const htmlPath = path.resolve('dist/report.html');

const browser = await puppeteer.launch({
  executablePath: edgeBinaryPath,
  headless: 'new',
  args: ['--allow-file-access-from-files']
});

const page = await browser.newPage();

await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), {
  waitUntil: 'networkidle0',
  timeout: 60000
});

const report = await page.evaluate(() => {
  const blocks = document.querySelectorAll('.mermaid');
  const details = [];
  blocks.forEach((b, idx) => {
    const hasError = b.querySelector('.error-icon, .error-text, svg[id*="mermaid-error"]') !== null || b.innerText.includes('Syntax error');
    const svg = b.querySelector('svg');
    const width = svg ? svg.getBoundingClientRect().width : 0;
    const height = svg ? svg.getBoundingClientRect().height : 0;
    details.push({
      index: idx + 1,
      hasError,
      svgWidth: Math.round(width),
      svgHeight: Math.round(height),
      snippet: b.textContent.trim().slice(0, 80).replace(/\n/g, ' ')
    });
  });
  return details;
});

console.log('--- MERMAID BLOCKS REPORT ---');
report.forEach(r => {
  const status = r.hasError ? '[FAILED]' : '[OK]';
  console.log(`${status} #${String(r.index).padStart(2, '0')} (w=${r.svgWidth}px, h=${r.svgHeight}px) | ${r.snippet}`);
});

await browser.close();
