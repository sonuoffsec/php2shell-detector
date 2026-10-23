import { describe, expect, it } from 'vitest';
import { loadAdvisories, loadBundledAdvisories } from '../../src/advisories';
import raw from '../../src/advisories/data/php2shell.json';
import { assess } from '../../src/assessment/engine';
import type { CollectResult } from '../../src/scanner/collect';
import { NOW, ORIGIN, snapshot } from '../helpers/fixtures';

const advisory = loadBundledAdvisories(NOW);
const run = (collect: CollectResult, adv = advisory) => assess({ requestedOrigin: ORIGIN, collect, advisory: adv, now: NOW });

describe('assessment engine - passive scenarios', () => {
  it('no PHP indicators visible → No indicators detected (never "safe")', () => {
    const a = run(snapshot({ server: 'nginx' }));
    expect(a.state).toBe('no-indicators');
    expect(a.rationale.join(' ')).toMatch(/NOT establish/);
    expect(a.confidence.level).toBe('low');
    expect(a.unknowns.join(' ')).toMatch(/PHP runs behind headers/);
  });

  it('affected upstream version → Potentially exposed with medium confidence', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP/8.3.30' }));
    expect(a.state).toBe('potentially-exposed');
    expect(a.ruleId).toBe('R08-AFFECTED-UPSTREAM');
    expect(a.evidence.find((e) => e.kind === 'php-version')?.versionProvenance).toBe('observed');
    expect(a.confidence.level).toBe('medium');
    expect(a.cves.map((c) => c.id)).toEqual(['CVE-2026-109618', 'CVE-2026-109619']);
  });

  it.each([
    ['8.5.11', 'potentially-exposed'],
    ['8.4.26', 'potentially-exposed'],
    ['8.2.34', 'potentially-exposed'],
    ['8.5.12RC1', 'potentially-exposed'],
    ['8.5.12', 'no-indicators'],
    ['8.4.27', 'no-indicators'],
    ['8.3.36', 'no-indicators'],
    ['8.2.35', 'no-indicators'],
    ['8.3.40', 'no-indicators'],
    ['8.6.0', 'no-indicators'],
  ])('PHP %s → %s', (version, expected) => {
    expect(run(snapshot({ 'x-powered-by': `PHP/${version}` })).state).toBe(expected);
  });

  it('fixed upstream version is NOT "patch verified"', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP/8.4.27' }));
    expect(a.state).toBe('no-indicators');
    expect(a.state).not.toBe('patch-verified');
    expect(a.rationale.join(' ')).toMatch(/not patch verification/);
  });

  it('version read from the Server header (mod_php style)', () => {
    const a = run(snapshot({ server: 'Apache/2.4.58 PHP/8.2.20' }));
    expect(a.state).toBe('potentially-exposed');
    expect(a.evidence.some((e) => e.source.name === 'server')).toBe(true);
  });

  it('missing version header with PHP app fingerprint → indicators, never a guessed version', () => {
    const a = run(snapshot({ link: '<https://example.test/wp-json/>; rel="https://api.w.org/"' }));
    expect(a.state).toBe('exposure-indicators');
    expect(a.evidence.every((e) => e.kind !== 'php-version')).toBe(true);
    expect(a.evidence.find((e) => e.kind === 'app-fingerprint')?.directness).toBe('inference');
    expect(a.evidence.find((e) => e.kind === 'app-fingerprint')?.versionProvenance).toBe('inferred');
  });

  it('x-powered-by: PHP with no version → indicators, patch level unknown', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP' }));
    expect(a.state).toBe('exposure-indicators');
    expect(a.ruleId).toBe('R16-PHP-NO-VERSION');
  });

  it('CDN with no PHP evidence → Inconclusive (not "no indicators")', () => {
    const a = run(snapshot({ server: 'cloudflare', 'cf-ray': 'abc-FRA' }));
    expect(a.state).toBe('inconclusive');
    expect(a.ruleId).toBe('R18-PROXY-OPAQUE');
    expect(a.evidence.find((e) => e.kind === 'proxy-cdn')?.doesNotProve.join(' ')).toMatch(/risk reduction/);
  });

  it('CDN + version header still reports exposure but with low evidence reliability and caveat', () => {
    const a = run(snapshot({ server: 'cloudflare', 'cf-ray': 'x', 'x-powered-by': 'PHP/8.2.10' }));
    expect(a.state).toBe('potentially-exposed');
    expect(a.evidence.find((e) => e.kind === 'php-version')?.reliability).toBe('low');
    expect(a.confidence.level).toBe('low');
    expect(a.rationale.join(' ')).toMatch(/CDN/);
  });

  it('vendor backport may apply: Ubuntu suffix on an affected version → exposure indicators', () => {
    const a = run(snapshot({ server: 'Apache/2.4.52 (Ubuntu)', 'x-powered-by': 'PHP/8.1.2-1ubuntu2.14' }));
    expect(a.state).toBe('exposure-indicators');
    expect(a.ruleId).toBe('R11-UNSUPPORTED-BACKPORT-POSSIBLE');
    expect(a.evidence.some((e) => e.kind === 'distro-marker')).toBe(true);
    const b = run(snapshot({ server: 'Apache/2.4.58 (Debian)', 'x-powered-by': 'PHP/8.3.10' }));
    expect(b.state).toBe('exposure-indicators');
    expect(b.ruleId).toBe('R10-AFFECTED-BACKPORT-POSSIBLE');
    expect(b.nextSteps.find((s) => s.id === 'verify-patch')?.detail).toMatch(/apt changelog/);
  });

  it('unsupported branch without vendor marker → Potentially exposed', () => {
    for (const v of ['7.4.33', '8.0.30', '8.1.31', '5.6.40']) {
      const a = run(snapshot({ 'x-powered-by': `PHP/${v}` }));
      expect(a.state, v).toBe('potentially-exposed');
      expect(a.ruleId).toBe('R09-UNSUPPORTED-BRANCH');
    }
    expect(run(snapshot({ 'x-powered-by': 'PHP/8.1.31' })).nextSteps.find((s) => s.id === 'apply-fix')?.detail).toMatch(/no upstream release/);
  });

  it('branch below 5.4 is outside the advisory scope', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP/5.3.29' }));
    expect(a.state).toBe('exposure-indicators');
    expect(a.ruleId).toBe('R13-BELOW-SCOPE');
  });

  it('branch-only disclosure → exposure indicators', () => {
    expect(run(snapshot({ 'x-powered-by': 'PHP/8.3' })).ruleId).toBe('R12-BRANCH-ONLY');
  });

  it('conflicting version signals → Inconclusive', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP/8.3.36', server: 'Apache PHP/7.4.33' }));
    expect(a.state).toBe('inconclusive');
    expect(a.ruleId).toBe('R04-CONFLICT');
  });

  it('same version in two headers is corroboration, not conflict', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP/8.3.30', server: 'Apache PHP/8.3.30' }));
    expect(a.state).toBe('potentially-exposed');
  });

  it('spoofed/garbage version does not produce a verdict', () => {
    expect(run(snapshot({ 'x-powered-by': 'PHP/99999.0' })).state).not.toBe('potentially-exposed');
    // PHP is named but the version is unusable → indicators, never a guessed version
    expect(run(snapshot({ 'x-powered-by': 'PHP/banana' })).state).toBe('exposure-indicators');
    expect(run(snapshot({ 'x-powered-by': 'PHP/99999.0' })).state).toBe('exposure-indicators');
  });

  it('error / bot-block page with no indicators → Inconclusive', () => {
    expect(run(snapshot({}, { status: 403 })).state).toBe('inconclusive');
    expect(run(snapshot({}, { status: 503 })).state).toBe('inconclusive');
  });

  it('request failure → Inconclusive with fetch-error evidence', () => {
    const a = run({ ok: false, kind: 'network', error: 'unreachable' });
    expect(a.state).toBe('inconclusive');
    expect(a.evidence[0]?.kind).toBe('fetch-error');
  });

  it('redirect to a different host → Inconclusive, final host evidence not applied to requested host', () => {
    const a = run(snapshot({ 'x-powered-by': 'PHP/8.0.1' }, { finalOrigin: 'https://other.test', redirected: true }));
    expect(a.state).toBe('inconclusive');
    expect(a.ruleId).toBe('R02-REDIRECT-HOST');
    expect(a.target.hostChanged).toBe(true);
    expect(a.evidence.some((e) => e.kind === 'redirect')).toBe(true);
  });

  it('http→https redirect on the same host is allowed but disclosed', () => {
    const a = assess({
      requestedOrigin: 'http://example.test',
      collect: snapshot({ 'x-powered-by': 'PHP/8.3.1' }, { finalOrigin: 'https://example.test', redirected: true }),
      advisory,
      now: NOW,
    });
    expect(a.state).toBe('potentially-exposed');
    expect(a.warnings.join(' ')).toMatch(/Redirected from http:\/\/example.test to https:\/\/example.test/);
  });
});

describe('advisory availability', () => {
  it('advisory data unavailable → Inconclusive, no version comparison', () => {
    const bad = loadAdvisories({ nope: true }, NOW);
    expect(bad.available).toBe(false);
    const a = run(snapshot({ 'x-powered-by': 'PHP/8.0.1' }), bad);
    expect(a.state).toBe('inconclusive');
    expect(a.ruleId).toBe('R06-ADVISORY-UNAVAILABLE');
    expect(a.cves).toEqual([]);
    expect(a.advisory.available).toBe(false);
  });

  const later = new Date('2027-03-01T00:00:00Z');
  const stale = loadBundledAdvisories(later);

  it('stale advisory data is disclosed and a "fixed" reading is downgraded to Inconclusive', () => {
    expect(stale.available && stale.stale).toBe(true);
    const fixed = assess({ requestedOrigin: ORIGIN, collect: snapshot({ 'x-powered-by': 'PHP/8.4.27' }), advisory: stale, now: later });
    expect(fixed.state).toBe('inconclusive');
    expect(fixed.ruleId).toBe('R15-FIXED-BUT-STALE');
    expect(fixed.warnings.join(' ')).toMatch(/stale/);
    expect(fixed.advisory.stale).toBe(true);
  });

  it('stale advisory still flags an affected version but warns', () => {
    const a = assess({ requestedOrigin: ORIGIN, collect: snapshot({ 'x-powered-by': 'PHP/8.4.1' }), advisory: stale, now: later });
    expect(a.state).toBe('potentially-exposed');
    expect(a.warnings.join(' ')).toMatch(/stale/);
    expect(a.confidence.level).toBe('low');
  });

  it('bundled dataset validates, is traceable, and has no complete-fix mitigations', () => {
    expect(advisory.available).toBe(true);
    if (!advisory.available) return;
    const adv = advisory.dataset.advisories[0]!;
    expect(adv.scope.supportedBranches.map((b) => b.fixedIn)).toEqual(['8.2.35', '8.3.36', '8.4.27', '8.5.12']);
    expect(advisory.dataset.references.every((r) => r.url.startsWith('https://') && r.checkedAt === '2026-10-23')).toBe(true);
    expect(adv.mitigations.every((m) => m.completeFix === false)).toBe(true);
    expect(adv.knownDiscrepancies.length).toBeGreaterThan(0);
  });

  it('rejects malformed advisory data (bad fixedIn branch, unknown reference)', () => {
    const bad = structuredClone(raw) as typeof raw;
    bad.advisories[0]!.scope.supportedBranches[0]!.fixedIn = '8.3.99';
    expect(loadAdvisories(bad, NOW).available).toBe(false);
    const bad2 = structuredClone(raw) as typeof raw;
    bad2.advisories[0]!.referenceIds.push('does-not-exist');
    expect(loadAdvisories(bad2, NOW).available).toBe(false);
  });
});
