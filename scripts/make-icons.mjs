// Builds extension icons from logo/PHP2.png (cropped to the artwork, resized with a headless Chromium canvas).
// Run: npm run icons   (set P2S_CHROME to a Chrome/Chromium binary if Playwright's bundled one isn't installed)
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const src = readFileSync('logo/PHP2.png').toString('base64');
mkdirSync('extension/static/icons', { recursive: true });

const browser = await chromium.launch(process.env.P2S_CHROME ? { executablePath: process.env.P2S_CHROME } : {});
const page = await browser.newPage();
const sizes = [16, 48, 128];
const out = await page.evaluate(
  async ({ src, sizes }) => {
    const img = new Image();
    img.src = `data:image/png;base64,${src}`;
    await img.decode();
    // Crop the empty margin around the shield+magnifier (source is 1254x1254).
    const crop = { x: 180, y: 130, s: 920 };
    return sizes.map((n) => {
      const c = document.createElement('canvas');
      c.width = c.height = n;
      const g = c.getContext('2d');
      g.imageSmoothingQuality = 'high';
      // step-down for quality at small sizes
      let cur = document.createElement('canvas');
      let size = crop.s;
      cur.width = cur.height = size;
      cur.getContext('2d').drawImage(img, crop.x, crop.y, crop.s, crop.s, 0, 0, size, size);
      while (size / 2 > n) {
        const next = document.createElement('canvas');
        next.width = next.height = Math.floor(size / 2);
        const ng = next.getContext('2d');
        ng.imageSmoothingQuality = 'high';
        ng.drawImage(cur, 0, 0, next.width, next.height);
        cur = next;
        size = next.width;
      }
      g.drawImage(cur, 0, 0, n, n);
      return c.toDataURL('image/png').split(',')[1];
    });
  },
  { src, sizes },
);
await browser.close();
sizes.forEach((n, i) => writeFileSync(`extension/static/icons/icon${n}.png`, Buffer.from(out[i], 'base64')));
console.log('icons written from logo/PHP2.png');
