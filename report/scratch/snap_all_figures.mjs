import puppeteer from 'puppeteer-core';
import fs from 'fs';
import path from 'path';

async function snapAll() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1754, deviceScaleFactor: 2 });
  
  const htmlPath = path.resolve('report/dist/report.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => window.__READY === true, { timeout: 30000 });
  await new Promise(r => setTimeout(r, 2000));

  const screenshotsDir = path.resolve('report/dist/screenshots');
  if (!fs.existsSync(screenshotsDir)) {
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  // 1. Fig 4 Architecture
  const fig4 = await page.$('#fig4-container');
  if (fig4) {
    await page.evaluate(el => el.scrollIntoView(), fig4);
    await new Promise(r => setTimeout(r, 500));
    await fig4.screenshot({ path: path.join(screenshotsDir, 'fig4_architecture.png') });
    await fig4.screenshot({ path: path.join(screenshotsDir, 'fig4_actual.png') });
    console.log('Saved fig4_architecture.png');
  }

  // 2. Fig 19 Quadrant Map
  const fig19 = await page.$('#fig19-container');
  if (fig19) {
    await page.evaluate(el => el.scrollIntoView(), fig19);
    await new Promise(r => setTimeout(r, 500));
    await fig19.screenshot({ path: path.join(screenshotsDir, 'fig19_quadrant.png') });
    await fig19.screenshot({ path: path.join(screenshotsDir, 'fig19_actual.png') });
    console.log('Saved fig19_quadrant.png');
  }

  // 3. XY Charts (Fig 16, 17, 18, 21)
  const xycharts = await page.$$('svg[aria-roledescription="xychart"]');
  console.log('Found xycharts count:', xycharts.length);
  for (let i = 0; i < xycharts.length; i++) {
    const chart = xycharts[i];
    await page.evaluate(el => el.scrollIntoView(), chart);
    await new Promise(r => setTimeout(r, 500));
    if (i === 0) {
      await chart.screenshot({ path: path.join(screenshotsDir, 'fig16_latency.png') });
      console.log('Saved fig16_latency.png');
    } else if (i === 1) {
      await chart.screenshot({ path: path.join(screenshotsDir, 'fig17_throughput.png') });
      console.log('Saved fig17_throughput.png');
    } else if (i === 2) {
      await chart.screenshot({ path: path.join(screenshotsDir, 'fig18_memory.png') });
      console.log('Saved fig18_memory.png');
    } else if (i === 3) {
      await chart.screenshot({ path: path.join(screenshotsDir, 'fig21_evasion.png') });
      console.log('Saved fig21_evasion.png');
    }
  }

  await browser.close();
  console.log('All figures snapped successfully!');
}

snapAll();
