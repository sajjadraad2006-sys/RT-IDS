import fs from 'fs';
import path from 'path';
import puppeteer from 'puppeteer-core';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../..');
const REPORT_DIR = path.resolve(ROOT_DIR, 'report');
const DIST_DIR = path.resolve(REPORT_DIR, 'dist');
const htmlPath = path.resolve(DIST_DIR, 'report.html');
const pdfPath = path.resolve(DIST_DIR, 'report.pdf');
const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

console.log('Launching Edge Chromium via Puppeteer...');
const browser = await puppeteer.launch({
  executablePath: edgePath,
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
page.on('console', msg => console.log('BROWSER CONSOLE:', msg.text()));
page.on('pageerror', err => console.error('BROWSER ERROR:', err.message));

console.log('Navigating to HTML file:', htmlPath);
const fileUrl = 'file:///' + htmlPath.replace(/\\/g, '/');

await page.goto(fileUrl, {
  waitUntil: 'domcontentloaded',
  timeout: 60000
});

console.log('DOM Content Loaded. Waiting for rendering / pagination...');

// Wait for Paged.js to finish or 15 seconds
try {
  await page.waitForFunction(() => {
    return document.documentElement.classList.contains('pagedjs_done') ||
           document.querySelectorAll('.pagedjs_page').length > 0;
  }, { timeout: 30000 });
  console.log('Paged.js pagination detected!');
} catch (e) {
  console.log('Paged.js wait timed out or class not present. Proceeding with standard layout...');
}

// Check page count in DOM if Paged.js ran
const pagedPageCount = await page.evaluate(() => {
  return document.querySelectorAll('.pagedjs_page').length;
});
console.log('Paged.js generated page elements count:', pagedPageCount);

console.log('Exporting PDF via page.pdf()...');
await page.pdf({
  path: pdfPath,
  format: 'A4',
  printBackground: true,
  preferCSSPageSize: true,
  timeout: 120000
});

await browser.close();

const stats = fs.statSync(pdfPath);
console.log(`Generated PDF successfully! Size: ${(stats.size / 1024).toFixed(1)} KB`);
