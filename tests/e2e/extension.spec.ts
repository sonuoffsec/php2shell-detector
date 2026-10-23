import { expect, test, type BrowserContext } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { buildReport, generateKey, signReport } from '../../tools/php2shell-attest.mjs';
import { launchWithExtension, openPopup } from '../helpers/extension';
import { originOf, startServer, type TestServer } from '../helpers/servers';

// Drives the built extension (dist-e2e) in real Chrome against loopback servers only.
let context: BrowserContext;
let id: string;
const servers: TestServer[] = [];

test.beforeAll(async () => {
  ({ context, id } = await launchWithExtension());
});
test.afterAll(async () => {
  await context.close();
  await Promise.all(servers.map((s) => s.close()));
});

async function assessWith(headers: Record<string, string>) {
  const s = await startServer({ headers });
  servers.push(s);
  const page = await openPopup(context, id);
  await page.getByLabel('Website to assess').fill(originOf(s));
  await page.getByRole('button', { name: 'Assess website' }).click();
  await expect(page.getByTestId('result')).toBeVisible();
  return { page, server: s };
}

test('extension loads and the popup renders with no placeholder results', async () => {
  const page = await openPopup(context, id);
  await expect(page.getByRole('heading', { name: 'PHP2Shell Detector' })).toBeVisible();
  await expect(page.getByText('Detect exposure. Verify the evidence.')).toBeVisible();
  await expect(page.getByTestId('result')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Assess website' })).toBeDisabled();
});

test('affected version on a local server → Potentially exposed with real evidence', async () => {
  const { page, server } = await assessWith({ 'X-Powered-By': 'PHP/8.3.12', 'Set-Cookie': 'PHPSESSID=E2ESECRETCOOKIE0123456789abcdef; path=/' });
  await expect(page.getByTestId('state-badge')).toHaveText(/Potentially exposed/);
  await expect(page.getByTestId('result')).toContainText('PHP 8.3.12');
  await expect(page.getByTestId('result')).toContainText('CVE-2026-109619');
  expect(await page.content()).not.toContain('E2ESECRETCOOKIE');
  expect(server.requests).toHaveLength(1);
  expect(server.requests[0]!.url).toBe('/');
  expect(server.requests[0]!.headers['cookie']).toBeUndefined();
  expect(server.requests[0]!.headers['authorization']).toBeUndefined();
});

test('fixed upstream header is "No indicators", never green "secure" or "Patch verified"', async () => {
  const { page } = await assessWith({ 'X-Powered-By': 'PHP/8.5.12' });
  await expect(page.getByTestId('state-badge')).toHaveText(/No indicators detected/);
  await expect(page.getByTestId('state-badge')).not.toHaveText(/secure|safe|patch verified/i);
  await expect(page.locator('.state-patch-verified')).toHaveCount(0);
  await expect(page.getByTestId('result')).toContainText('This is not patch verification');
});

test('CDN hiding the origin → Inconclusive', async () => {
  const { page } = await assessWith({ Server: 'cloudflare', 'CF-RAY': 'e2e-AMS' });
  await expect(page.getByTestId('state-badge')).toHaveText(/Inconclusive/);
});

test('JSON export is redacted and matches the assessment', async () => {
  const { page } = await assessWith({ 'X-Powered-By': 'PHP/8.2.20', 'Set-Cookie': 'sid=E2ELEAKCHECK0123456789abcdef0123' });
  await page.getByRole('button', { name: /Export report/ }).click();
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download JSON' }).click()]);
  const path = await download.path();
  const text = readFileSync(path, 'utf8');
  const json = JSON.parse(text);
  expect(json.assessment.state).toBe('potentially-exposed');
  expect(json.target.requestedOrigin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  expect(text).not.toContain('E2ELEAKCHECK');
  expect(text).not.toMatch(/set-cookie/i);
});

test('owner report: unsigned is self-reported; signed by a trusted key reaches Patch verified', async () => {
  const { page, server } = await assessWith({ 'X-Powered-By': 'PHP/8.3.36' });
  const origin = originOf(server);
  const key = generateKey();
  const report = buildReport({ origin, phpVersion: '8.3.36', packageSourceType: 'upstream-source', patchStatus: 'fixed-upstream', workersRestarted: true });

  await page.getByRole('tab', { name: 'Owner verification' }).click();
  await page.locator('#report-text').fill(JSON.stringify(report));
  await page.getByRole('button', { name: 'Validate & apply' }).click();
  await expect(page.getByTestId('owner-summary')).toContainText('self-reported');
  await expect(page.getByTestId('owner-summary')).toContainText('No - kept as an unverified claim');

  await page.locator('#report-text').fill(JSON.stringify(signReport(report, key)));
  await page.getByRole('button', { name: 'Validate & apply' }).click();
  await expect(page.getByRole('button', { name: /I verified this fingerprint/ })).toBeVisible();
  await page.getByRole('button', { name: /I verified this fingerprint/ }).click();
  await expect(page.getByTestId('owner-summary')).toContainText('attested');

  await page.getByRole('tab', { name: 'Assessment' }).click();
  await expect(page.getByTestId('state-badge')).toHaveText(/Patch verified/);
  await expect(page.getByTestId('result')).toContainText('not that it is true');

  // tampered report is rejected outright
  const tampered = signReport(report, key) as unknown as { runtime: { phpVersion: string } };
  tampered.runtime.phpVersion = '8.3.99';
  await page.getByRole('tab', { name: 'Owner verification' }).click();
  await page.locator('#report-text').fill(JSON.stringify(tampered));
  await page.getByRole('button', { name: 'Validate & apply' }).click();
  await expect(page.getByTestId('owner-errors')).toContainText('Invalid signature');
});

test('malformed URL is refused client-side', async () => {
  const page = await openPopup(context, id);
  await page.getByLabel('Website to assess').fill('ftp://example.com');
  await expect(page.getByRole('button', { name: 'Assess website' })).toBeDisabled();
  await expect(page.getByTestId('origin-line')).toContainText('Only http and https');
});
