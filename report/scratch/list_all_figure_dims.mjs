import puppeteer from 'puppeteer-core';
import path from 'path';

const edgeBinaryPath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const htmlPath = path.resolve('report/dist/report.html');

async function run() {
  const browser = await puppeteer.launch({
    executablePath: edgeBinaryPath,
    headless: 'new',
    args: ['--no-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1754 });
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0', timeout: 60000 });
  await page.waitForFunction(() => window.__READY === true, { timeout: 30000 });

  const figures = await page.evaluate(() => {
    const list = [];
    document.querySelectorAll('.mermaid, #fig4-container, #fig19-container').forEach((el, i) => {
      // Find following caption
      let next = el.parentElement;
      while (next && !next.querySelector('.figure-caption, b')) {
        next = next.nextElementSibling;
      }
      let caption = next ? next.innerText.trim() : 'No caption found';
      const svg = el.querySelector('svg');
      if (svg) {
        const rect = svg.getBoundingClientRect();
        const vb = svg.getAttribute('viewBox') || '';
        list.push({
          num: i + 1,
          caption: caption.split('\n')[0].substring(0, 80),
          width: Math.round(rect.width),
          height: Math.round(rect.height),
          aspectRatio: (rect.width / (rect.height || 1)).toFixed(2),
          viewBox: vb
        });
      }
    });
    return list;
  });

  console.table(figures);
  await browser.close();
}

run().catch(console.error);
