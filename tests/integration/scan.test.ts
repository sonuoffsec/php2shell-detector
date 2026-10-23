import { createServer } from 'node:http';
import { afterAll, describe, expect, it } from 'vitest';
import { runAssessment } from '../../src/assessment/run';
import { collectSnapshot } from '../../src/scanner/collect';
import { originOf, startServer, type TestServer } from '../helpers/servers';

const servers: TestServer[] = [];
const serve = async (...a: Parameters<typeof startServer>) => {
  const s = await startServer(...a);
  servers.push(s);
  return s;
};
afterAll(async () => {
  await Promise.all(servers.map((s) => s.close()));
});

describe('passive scan against synthetic local servers', () => {
  it('affected version → Potentially exposed, with exactly one clean GET /', async () => {
    const s = await serve({ headers: { 'X-Powered-By': 'PHP/8.2.20', 'Set-Cookie': 'PHPSESSID=SECRETSESSION0123456789abcdef0123; path=/' } });
    const r = await runAssessment(originOf(s) + '/some/deep/path?token=SECRET#frag');
    expect(r.ok && r.assessment.state).toBe('potentially-exposed');

    expect(s.requests).toHaveLength(1);
    const req = s.requests[0]!;
    expect(req.method).toBe('GET');
    expect(req.url).toBe('/'); // path, query, fragment are never sent
    expect(req.headers['cookie']).toBeUndefined();
    expect(req.headers['authorization']).toBeUndefined();
    expect(req.headers['referer']).toBeUndefined();
    expect(req.headers['origin']).toBeUndefined();
    expect(JSON.stringify(r)).not.toContain('SECRETSESSION');
  });

  it('fixed upstream version → No indicators (not Patch verified)', async () => {
    const s = await serve({ headers: { 'X-Powered-By': 'PHP/8.4.27' } });
    const r = await runAssessment(originOf(s));
    expect(r.ok && r.assessment.state).toBe('no-indicators');
  });

  it('missing version header → no PHP indicators, honest wording', async () => {
    const s = await serve({ headers: { Server: 'nginx' } });
    const r = await runAssessment(originOf(s));
    expect(r.ok && r.assessment.state).toBe('no-indicators');
  });

  it('WordPress fingerprint without version → Exposure indicators', async () => {
    const s = await serve({ headers: { Link: `<http://x.test/wp-json/>; rel="https://api.w.org/"` } });
    const r = await runAssessment(originOf(s));
    expect(r.ok && r.assessment.state).toBe('exposure-indicators');
  });

  it('CDN headers + no PHP → Inconclusive', async () => {
    const s = await serve({ headers: { Server: 'cloudflare', 'CF-RAY': '8a1b2c3d-AMS' } });
    const r = await runAssessment(originOf(s));
    expect(r.ok && r.assessment.state).toBe('inconclusive');
  });

  it('spoofed version is taken at face value but labelled as an unverified observation', async () => {
    const s = await serve({ headers: { 'X-Powered-By': 'PHP/8.5.12', Server: 'Apache/2.4 PHP/5.6.40' } });
    const r = await runAssessment(originOf(s));
    expect(r.ok && r.assessment.state).toBe('inconclusive'); // conflicting claims
  });

  it('redirect to another host → Inconclusive; the destination is not treated as the target', async () => {
    const dest = await serve({ headers: { 'X-Powered-By': 'PHP/7.4.33' } });
    const src = await serve({ redirectTo: `http://localhost:${dest.port}/landing` });
    const r = await runAssessment(originOf(src, '127.0.0.1'));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.assessment.target.hostChanged).toBe(true);
    expect(r.assessment.target.finalOrigin).toBe(`http://localhost:${dest.port}`);
    expect(r.assessment.state).toBe('inconclusive');
    expect(r.assessment.ruleId).toBe('R02-REDIRECT-HOST');
  });

  it('malformed URL → error, no request made', async () => {
    const s = await serve({});
    const r = await runAssessment('ht!tp://bad host');
    expect(r.ok).toBe(false);
    expect(s.requests).toHaveLength(0);
  });

  it('unreachable target → Inconclusive with a fetch-error evidence item', async () => {
    const s = await startServer({});
    const origin = originOf(s);
    await s.close();
    const r = await runAssessment(origin, { timeoutMs: 1500 });
    expect(r.ok && r.assessment.state).toBe('inconclusive');
    expect(r.ok && r.assessment.evidence[0]?.kind).toBe('fetch-error');
  });

  it('hanging server → timeout, Inconclusive', async () => {
    const hang = createServer(() => undefined);
    await new Promise<void>((r) => hang.listen(0, '127.0.0.1', r));
    const port = (hang.address() as { port: number }).port;
    const res = await collectSnapshot(`http://127.0.0.1:${port}`, { timeoutMs: 200 });
    expect(res).toMatchObject({ ok: false, kind: 'timeout' });
    hang.closeAllConnections();
    await new Promise((r) => hang.close(r));
  });

  it('works without any backend: the target is the only host contacted', async () => {
    const s = await serve({ headers: { 'X-Powered-By': 'PHP/8.3.1' } });
    const urls: string[] = [];
    const spy: typeof fetch = (input, init) => {
      urls.push(String(input));
      return fetch(input, init);
    };
    const r = await runAssessment(originOf(s), { fetchImpl: spy });
    expect(r.ok).toBe(true);
    expect(urls).toEqual([`${originOf(s)}/`]);
  });
});
