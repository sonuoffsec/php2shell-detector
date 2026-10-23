import { describe, expect, it } from 'vitest';
import { assess } from '../../src/assessment/engine';
import { loadBundledAdvisories } from '../../src/advisories';
import { minimizeHeaders, redactDeep, REDACTED, scrubValue } from '../../src/privacy/redact';
import { buildJsonReport } from '../../src/reports/json';
import { buildTextReport } from '../../src/reports/text';
import { parseTarget } from '../../src/scanner/target';
import { NOW, ORIGIN, snapshot } from '../helpers/fixtures';

describe('target handling', () => {
  it.each([
    ['https://Example.com/path?q=1#x', 'https://example.com'],
    ['http://example.com:8080/a', 'http://example.com:8080'],
    ['example.com', 'https://example.com'],
    ['example.com:8443/x', 'https://example.com:8443'],
    ['https://example.com:443', 'https://example.com'],
    ['http://127.0.0.1:3000', 'http://127.0.0.1:3000'],
    ['https://bücher.example', 'https://xn--bcher-kva.example'],
  ])('normalises %s', (input, origin) => {
    const r = parseTarget(input);
    expect(r.ok && r.origin).toBe(origin);
  });

  it.each([
    [''],
    ['   '],
    ['http://'],
    ['not a url'],
    ['ftp://example.com'],
    ['javascript:alert(1)'],
    ['file:///etc/passwd'],
    ['chrome://settings'],
    ['https://user:pass@example.com'],
    ['https://exa mple.com'],
    ['http://[::1'],
  ])('rejects malformed or unsupported input %j', (input) => {
    const r = parseTarget(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.length).toBeGreaterThan(5);
  });
});

describe('privacy / redaction', () => {
  it('keeps only allowlisted headers and redacts sensitive ones', () => {
    const h = minimizeHeaders(
      Object.entries({
        'Set-Cookie': 'PHPSESSID=abcdef1234567890abcdef1234567890; HttpOnly',
        Authorization: 'Bearer abcdefghijklmnop',
        'X-Api-Key': 'sk_live_123',
        'Content-Type': 'text/html',
        Date: 'x',
        'X-Powered-By': 'PHP/8.3.1',
        Server: 'nginx',
      }),
    );
    expect(h['set-cookie']).toBe(REDACTED);
    expect(h['authorization']).toBe(REDACTED);
    expect(h['x-api-key']).toBe(REDACTED);
    expect(h['content-type']).toBeUndefined();
    expect(h['date']).toBeUndefined();
    expect(h['x-powered-by']).toBe('PHP/8.3.1');
    expect(JSON.stringify(h)).not.toContain('abcdef1234567890');
  });

  it('scrubs URL query strings, bearer tokens, long hex, JWTs and URL credentials', () => {
    expect(scrubValue('<https://a.test/wp-json/?token=SECRET&x=1>; rel="x"')).not.toContain('SECRET');
    expect(scrubValue('Bearer abcdefghijklmnop')).toContain(REDACTED);
    expect(scrubValue('id 0123456789abcdef0123456789abcdef0123')).toContain(REDACTED);
    expect(scrubValue('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc')).toBe(REDACTED);
  });

  it('exports never contain cookies, credentials, auth headers, bodies or URL secrets', () => {
    const a = assess({
      requestedOrigin: ORIGIN,
      collect: snapshot({
        'x-powered-by': 'PHP/8.3.1',
        'set-cookie': 'PHPSESSID=SECRETCOOKIEVALUE0123456789abcdef; path=/',
        authorization: 'Bearer SUPERSECRETTOKEN123',
        link: '<https://example.test/wp-json/?auth=LEAK123>; rel="https://api.w.org/"',
      }),
      advisory: loadBundledAdvisories(NOW),
      now: NOW,
    });
    const json = JSON.stringify(buildJsonReport(a, NOW));
    const text = buildTextReport(a, NOW);
    for (const secret of ['SECRETCOOKIEVALUE', 'SUPERSECRETTOKEN', 'LEAK123']) {
      expect(json).not.toContain(secret);
      expect(text).not.toContain(secret);
    }
    expect(json).not.toMatch(/set-cookie|authorization|cookie:/i);
    expect(json).not.toContain('<html');
  });

  it('redactDeep redacts sensitive keys anywhere in a structure', () => {
    const out = redactDeep({ a: { 'Set-Cookie': 'x', ok: 'fine' }, list: [{ Authorization: 'y' }] });
    expect(out.a['Set-Cookie']).toBe(REDACTED);
    expect(out.list[0]!.Authorization).toBe(REDACTED);
    expect(out.a.ok).toBe('fine');
  });
});

describe('report accuracy', () => {
  const a = assess({ requestedOrigin: ORIGIN, collect: snapshot({ 'x-powered-by': 'PHP/8.3.30', server: 'nginx' }), advisory: loadBundledAdvisories(NOW), now: NOW });
  it('JSON report carries every required field and matches the assessment', () => {
    const r = buildJsonReport(a, NOW) as Record<string, any>;
    expect(r.target.requestedOrigin).toBe(ORIGIN);
    expect(r.assessedAt).toBe(NOW.toISOString());
    expect(r.assessment.state).toBe('potentially-exposed');
    expect(r.evidence[0]).toHaveProperty('reliability');
    expect(r.evidence.find((e: any) => e.kind === 'php-version').doesNotProve.length).toBeGreaterThan(0);
    expect(r.cves.map((c: any) => c.id)).toContain('CVE-2026-109618');
    expect(r.unverifiedAssumptions.length).toBeGreaterThan(0);
    expect(r.recommendedActions.length).toBeGreaterThan(3);
    expect(r.references.every((x: any) => x.url.startsWith('https://'))).toBe(true);
    expect(r.confidence.note).toMatch(/not a probability/);
  });
  it('text report states the state, the limits and sources', () => {
    const t = buildTextReport(a, NOW);
    expect(t).toContain('Potentially exposed');
    expect(t).toContain('CVE-2026-109619');
    expect(t).toContain('Unverified assumptions');
    expect(t).toContain('not proof that a server is vulnerable or safe');
    expect(t).toContain('https://www.php.net/archive/2026.php');
  });
});
