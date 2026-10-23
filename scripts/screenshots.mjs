// Captures screenshots of the REAL built extension (dist-e2e) against synthetic loopback servers.
// Usage: npm run build:e2e && P2S_CHROME=<chrome> node scripts/screenshots.mjs
import { chromium } from '@playwright/test';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { buildReport, generateKey, signReport } from '../tools/php2shell-attest.mjs';

const EXT = resolve('dist-e2e');
const OUT = resolve('docs/screenshots');
mkdirSync(OUT, { recursive: true });

const manifest = JSON.parse(readFileSync(join(EXT, 'manifest.json'), 'utf8'));
const hex = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32);
const id = [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join('');

const serve = (headers) =>
  new Promise((res) => {
    const s = createServer((_, r) => (r.writeHead(200, { 'content-type': 'text/html', ...headers }), r.end('<html>fixture</html>')));
    s.listen(0, '127.0.0.1', () => res({ s, origin: `http://127.0.0.1:${s.address().port}` }));
  });

const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'p2s-shot-')), {
  ...(process.env.P2S_CHROME ? { executablePath: process.env.P2S_CHROME } : { channel: 'chromium' }),
  headless: true,
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
  viewport: { width: 440, height: 780 },
  deviceScaleFactor: 2,
});

async function assess(headers, name, { after } = {}) {
  const { s, origin } = await serve(headers);
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${id}/popup.html`);
  await page.getByLabel('Website to assess').fill(origin);
  await page.getByRole('button', { name: 'Assess website' }).click();
  await page.getByTestId('result').waitFor();
  if (after) await after(page, origin);
  await page.screenshot({ path: join(OUT, `${name}.png`), fullPage: false });
  await page.screenshot({ path: join(OUT, `${name}-full.png`), fullPage: true });
  await page.close();
  s.close();
}

await assess({ 'X-Powered-By': 'PHP/8.3.12', Server: 'nginx' }, '01-potentially-exposed');
await assess({ Server: 'Apache/2.4.52 (Ubuntu)', 'X-Powered-By': 'PHP/8.1.2-1ubuntu2.14' }, '02-exposure-indicators-backport');
await assess({ Server: 'cloudflare', 'CF-RAY': '8a1b2c3d4e-AMS' }, '03-inconclusive-cdn');
await assess({ 'X-Powered-By': 'PHP/8.5.12' }, '04-no-indicators');
await assess({ 'X-Powered-By': 'PHP/8.3.36' }, '05-patch-verified', {
  after: async (page, origin) => {
    const key = generateKey();
    const report = signReport(
      buildReport({ origin, phpVersion: '8.3.36', packageSourceType: 'upstream-source', patchStatus: 'fixed-upstream', workersRestarted: true, osName: 'Debian', osVersion: '12' }),
      key,
    );
    await page.getByRole('tab', { name: 'Owner verification' }).click();
    await page.locator('#report-text').fill(JSON.stringify(report));
    await page.getByRole('button', { name: 'Validate & apply' }).click();
    await page.getByRole('button', { name: /I verified this fingerprint/ }).click();
    await page.getByTestId('owner-summary').waitFor();
    await page.screenshot({ path: join(OUT, '06-owner-verification.png'), fullPage: true });
    await page.getByRole('tab', { name: 'Assessment' }).click();
  },
});
await assess({ 'X-Powered-By': 'PHP/8.3.1' }, '07-mitigation-detected', {
  after: async (page, origin) => {
    const report = buildReport({ origin, phpVersion: '8.3.1', packageSourceType: 'other', patchStatus: 'not-patched', workersRestarted: true, mitigations: ['memory-limit-unlimited', 'upload-progress-disabled'] });
    await page.getByRole('tab', { name: 'Owner verification' }).click();
    await page.locator('#report-text').fill(JSON.stringify(report));
    await page.getByRole('button', { name: 'Validate & apply' }).click();
    await page.getByRole('tab', { name: 'Assessment' }).click();
  },
});
const page = await ctx.newPage();
await page.goto(`chrome-extension://${id}/popup.html`);
await page.getByRole('tab', { name: 'Privacy & method' }).click();
await page.screenshot({ path: join(OUT, '08-privacy-method.png'), fullPage: true });

// Chrome Web Store listing images: 1280x800, a popup capture next to a short caption.
const STORE = resolve('store/screenshots');
mkdirSync(STORE, { recursive: true });
const captions = {
  '01-potentially-exposed': ['Evidence first', 'See the header that was observed, where it came from and what it cannot prove.'],
  '02-exposure-indicators-backport': ['Backport aware', 'A distro version string means a vendor fix may already be installed.'],
  '03-inconclusive-cdn': ['Honest results', 'A CDN hides the origin, so the answer is Inconclusive, not Safe.'],
  '05-patch-verified': ['Owner verification', 'Only a signed report from a key you trust can reach Patch verified.'],
  '08-privacy-method': ['Private by design', 'One request to the site you pick. No backend, no analytics.'],
};
const shot = await ctx.newPage();
await shot.setViewportSize({ width: 1280, height: 800 });
let n = 1;
for (const [name, [title, text]] of Object.entries(captions)) {
  const img = readFileSync(join(OUT, `${name}.png`)).toString('base64');
  await shot.setContent(`<body style="margin:0;width:1280px;height:800px;background:#0f1218;display:flex;align-items:center;gap:64px;padding:0 96px;box-sizing:border-box;font-family:system-ui,sans-serif;color:#e6e9f0">
    <div style="flex:1"><div style="color:#22d3ee;font-size:20px;margin-bottom:12px">PHP2Shell Detector</div>
    <div style="font-size:52px;font-weight:700;line-height:1.1;margin-bottom:20px">${title}</div>
    <div style="font-size:24px;color:#9aa3b5;line-height:1.4">${text}</div></div>
    <img src="data:image/png;base64,${img}" style="height:720px;width:405px;object-fit:cover;object-position:top;border:1px solid #2a3140;border-radius:12px"></body>`);
  // The store wants exactly 1280x800 with no alpha: capture at CSS scale and save as JPEG.
  await shot.screenshot({ path: join(STORE, `${String(n++).padStart(2, '0')}-${name.replace(/^\d+-/, '')}.jpg`), type: 'jpeg', quality: 95, scale: 'css' });
}

await ctx.close();
console.log('screenshots written to', OUT, 'and', STORE);
