import puppeteer from 'puppeteer-core';

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.goto('file:///C:/Users/wwwsa/OneDrive/Desktop/sec/report/dist/report.html', { waitUntil: 'networkidle0' });
await page.waitForFunction(() => window.__READY === true);

const found = await page.evaluate(() => {
  const captions = Array.from(document.querySelectorAll('.figure-caption, figcaption, div'));
  for (const c of captions) {
    if (c.textContent && c.textContent.includes('Fig. 8.')) {
      const parent = c.parentElement;
      const svg = parent.querySelector('svg');
      if (svg) {
        svg.setAttribute('id', 'target-fig8-svg');
        return true;
      }
    }
  }
  return false;
});

if (found) {
  const el = await page.$('#target-fig8-svg');
  if (el) {
    await el.screenshot({ path: 'report/scratch/report_fig8_live.png' });
    console.log('Successfully captured report_fig8_live.png');
  }
} else {
  console.log('Fig 8 caption not found directly.');
}

await browser.close();
