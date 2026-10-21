import puppeteer from 'puppeteer-core';
import path from 'path';

async function capture() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: 'new',
    args: ['--no-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1000 });
  const htmlPath = path.resolve('report/scratch/test_fig5_svg.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
  const el = await page.$('#fig5-container svg');
  if (el) {
    await el.screenshot({ path: 'report/scratch/test_fig5_rendered.png' });
    console.log('Saved test_fig5_rendered.png');
  }
  await browser.close();
}
capture().catch(console.error);
