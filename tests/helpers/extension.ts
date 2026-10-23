import { chromium, type BrowserContext, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export const EXT_DIR = resolve('dist-e2e');

/** Chrome derives the extension ID from the manifest "key": sha256(DER)[0..16] mapped 0-f → a-p. */
export function extensionId(): string {
  const manifest = JSON.parse(readFileSync(join(EXT_DIR, 'manifest.json'), 'utf8')) as { key: string };
  const hex = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32);
  return [...hex].map((c) => String.fromCharCode('a'.charCodeAt(0) + parseInt(c, 16))).join('');
}

export async function launchWithExtension(): Promise<{ context: BrowserContext; id: string }> {
  const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'p2s-e2e-')), {
    // Set P2S_CHROME to use a specific Chrome/Chromium binary instead of Playwright's bundled one.
    ...(process.env.P2S_CHROME ? { executablePath: process.env.P2S_CHROME } : { channel: 'chromium' as const }), // new headless mode: supports extensions
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
    viewport: { width: 480, height: 900 },
  });
  return { context, id: extensionId() };
}

export async function openPopup(context: BrowserContext, id: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${id}/popup.html`);
  return page;
}
