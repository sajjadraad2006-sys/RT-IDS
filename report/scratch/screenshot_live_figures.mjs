import puppeteer from 'puppeteer-core';

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.goto('file:///C:/Users/wwwsa/OneDrive/Desktop/sec/report/dist/report.html', { waitUntil: 'networkidle0' });
await page.waitForFunction(() => window.__READY === true);

// Find Fig 8 diagram
const fig8 = await page.$('.mermaid-diagram:nth-of-type(5), #fig8-container, svg[aria-roledescription="sequenceDiagram"]');
if (fig8) {
  await fig8.screenshot({ path: 'report/scratch/report_fig8_live.png' });
  console.log('Saved report_fig8_live.png');
}

// Screenshot Fig 11 from the live report
const fig11 = await page.$('#fig11-container');
if (fig11) {
  await fig11.screenshot({ path: 'report/scratch/report_fig11_live.png' });
  console.log('Saved report_fig11_live.png');
}

await browser.close();
