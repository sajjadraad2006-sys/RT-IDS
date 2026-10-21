import puppeteer from 'puppeteer-core';

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.goto('file:///C:/Users/wwwsa/OneDrive/Desktop/sec/report/dist/report.html', { waitUntil: 'networkidle0' });
await page.waitForFunction(() => window.__READY === true);

const svgs = await page.evaluate(() => {
  const list = [];
  document.querySelectorAll('svg').forEach((svg, idx) => {
    // Find nearest preceding or succeeding text
    let container = svg.closest('.figure-container') || svg.closest('.mermaid-diagram') || svg.parentElement;
    let caption = container.querySelector('.figure-caption, figcaption, b, strong')?.textContent?.trim();
    if (!caption) {
      // Find nearest h2 or h3 or figure caption in document flow
      let prev = svg.parentElement;
      while (prev && !caption) {
        caption = prev.querySelector('.figure-caption, figcaption')?.textContent?.trim();
        prev = prev.previousElementSibling;
      }
    }
    const rect = svg.getBoundingClientRect();
    list.push({
      idx,
      cap: caption ? caption.substring(0, 60) : '',
      w: Math.round(rect.width),
      h: Math.round(rect.height),
      ar: (rect.width / (rect.height || 1)).toFixed(2),
      vb: svg.getAttribute('viewBox')
    });
  });
  return list;
});

console.table(svgs);
await browser.close();
