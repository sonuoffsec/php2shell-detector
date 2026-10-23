import { describe, expect, it } from 'vitest';
import { loadBundledAdvisories } from '../../src/advisories';
import { assess } from '../../src/assessment/engine';
import { evaluateOwnerReport } from '../../src/verification/evaluate';
import { canonicalize } from '../../src/verification/signature';
import { buildReport, canonicalize as cliCanonicalize, generateKey, signReport } from '../../tools/php2shell-attest.mjs';
import { NOW, ORIGIN, snapshot } from '../helpers/fixtures';

const advisory = loadBundledAdvisories(NOW);
const key = generateKey();
const otherKey = generateKey();
const trusted = new Set([key.keyId]);
const base = (over: Record<string, unknown> = {}) =>
  buildReport({
    origin: ORIGIN,
    phpVersion: '8.3.36',
    packageSourceType: 'upstream-source',
    patchStatus: 'fixed-upstream',
    workersRestarted: true,
    now: new Date('2026-10-24T00:00:00Z'),
    ...over,
  });
const evalReport = (r: unknown, t: ReadonlySet<string> = trusted) =>
  evaluateOwnerReport(typeof r === 'string' ? r : JSON.stringify(r), { assessedOrigin: ORIGIN, advisory, trustedKeyIds: t, now: NOW });
const passive = snapshot({ 'x-powered-by': 'PHP/8.3.30' });
const withOwner = async (r: unknown, collect = passive, t: ReadonlySet<string> = trusted) =>
  assess({ requestedOrigin: ORIGIN, collect, advisory, owner: await evalReport(r, t), now: NOW });

describe('owner verification reports', () => {
  it('CLI and extension canonicalisation agree', () => {
    const v = { b: [1, { z: 1, a: undefined, c: 'x' }], a: null };
    expect(cliCanonicalize(v)).toBe(canonicalize(v));
  });

  it('rejects invalid JSON and invalid schema', async () => {
    expect((await evalReport('{nope')).accepted).toBe(false);
    const o = await evalReport({ schema: 'wrong' });
    expect(o.accepted).toBe(false);
    const missing = base();
    delete (missing as any).patch;
    expect((await evalReport(missing)).accepted).toBe(false);
    const extra = { ...base(), surprise: 1 };
    expect((await evalReport(extra)).accepted).toBe(false);
    const badVersion = base({ phpVersion: '8.3' });
    expect((await evalReport(badVersion)).accepted).toBe(false);
    const httpRef = base({ vendorAdvisory: 'http://insecure.example/x' });
    expect((await evalReport(httpRef)).accepted).toBe(false);
  });

  it('rejects an invalid signature outright (tampered content)', async () => {
    const signed = signReport(base(), key) as any;
    signed.runtime.phpVersion = '8.3.99';
    const o = await evalReport(signed);
    expect(o.accepted).toBe(false);
    if (!o.accepted) expect(o.errors[0]).toMatch(/Invalid signature/);
  });

  it('rejects a keyId/publicKey mismatch and garbage signatures', async () => {
    const signed = signReport(base(), key) as any;
    signed.signature.keyId = otherKey.keyId;
    expect((await evalReport(signed)).accepted).toBe(false);
    const signed2 = signReport(base(), key) as any;
    signed2.signature.value = 'AAAA';
    expect((await evalReport(signed2)).accepted).toBe(false);
  });

  it('rejects a report for a different origin and a future timestamp', async () => {
    expect((await evalReport(signReport(base({ origin: 'https://evil.test' }), key))).accepted).toBe(false);
    expect((await evalReport(signReport(base({ now: new Date('2027-01-01T00:00:00Z') }), key))).accepted).toBe(false);
  });

  it('unsigned patch claim is labelled self-reported and does NOT reach Patch verified', async () => {
    const a = await withOwner(base());
    expect(a.state).toBe('potentially-exposed');
    expect(a.owner?.provenance).toBe('self-reported');
    expect(a.owner?.credited).toBe(false);
    expect(a.owner?.blockers.join(' ')).toMatch(/unsigned/);
    expect(a.evidence.find((e) => e.kind === 'owner-report')?.directness).toBe('self-reported');
    expect(a.evidence.find((e) => e.kind === 'owner-report')?.versionProvenance).toBe('admin-supplied');
  });

  it('valid signature from an UNTRUSTED key is not credited', async () => {
    const a = await withOwner(signReport(base(), otherKey));
    expect(a.state).not.toBe('patch-verified');
    expect(a.owner?.signature).toMatch(/UNTRUSTED/);
    expect(a.owner?.provenance).toBe('self-reported');
  });

  it('signed by a trusted key + fixed version + workers restarted → Patch verified (attested, with caveats)', async () => {
    const a = await withOwner(signReport(base(), key), snapshot({ 'x-powered-by': 'PHP/8.3.36' }));
    expect(a.state).toBe('patch-verified');
    expect(a.owner?.provenance).toBe('attested');
    expect(a.confidence.level).toBe('high');
    expect(a.rationale.join(' ')).toMatch(/not that it is true/);
    expect(a.evidence.find((e) => e.kind === 'owner-report')?.doesNotProve.join(' ')).toMatch(/extension inspected/i);
  });

  it('trusted + patched but public header shows a different version → Inconclusive (conflict)', async () => {
    const a = await withOwner(signReport(base(), key), passive);
    expect(a.state).toBe('inconclusive');
    expect(a.ruleId).toBe('O03-OWNER-CONFLICT');
  });

  it('patch verified without any public version evidence', async () => {
    const a = await withOwner(signReport(base(), key), snapshot({ server: 'nginx' }));
    expect(a.state).toBe('patch-verified');
  });

  it('refuses to credit: workers not restarted, inconsistent version, stale report', async () => {
    const nr = await withOwner(signReport(base({ workersRestarted: false }), key), snapshot({}));
    expect(nr.state).not.toBe('patch-verified');
    expect(nr.owner?.blockers.join(' ')).toMatch(/restarted/);
    const inconsistent = await withOwner(signReport(base({ phpVersion: '8.3.30' }), key), snapshot({}));
    expect(inconsistent.state).not.toBe('patch-verified');
    expect(inconsistent.owner?.blockers.join(' ')).toMatch(/Inconsistent/);
    const old = await withOwner(signReport(base({ now: new Date('2026-08-01T00:00:00Z') }), key), snapshot({}));
    expect(old.state).not.toBe('patch-verified');
    expect(old.owner?.blockers.join(' ')).toMatch(/days old/);
  });

  it('vendor backport requires an advisory ref, package name and package version', async () => {
    const incomplete = await withOwner(
      signReport(base({ phpVersion: '8.1.2-1ubuntu2.20', patchStatus: 'vendor-backport-applied', packageSourceType: 'distro-package' }), key),
      snapshot({}),
    );
    expect(incomplete.state).not.toBe('patch-verified');
    const ok = await withOwner(
      signReport(
        base({
          phpVersion: '8.1.2-1ubuntu2.20',
          patchStatus: 'vendor-backport-applied',
          packageSourceType: 'distro-package',
          packageName: 'Ubuntu php8.1',
          packageVersion: '8.1.2-1ubuntu2.20',
          vendorAdvisory: 'https://ubuntu.com/security/notices/EXAMPLE',
        }),
        key,
      ),
      snapshot({ server: 'Apache (Ubuntu)', 'x-powered-by': 'PHP/8.1.2-1ubuntu2.20' }),
    );
    expect(ok.state).toBe('patch-verified');
  });

  it('mitigation report → Mitigation detected, explicitly not patched', async () => {
    const a = await withOwner(base({ patchStatus: 'not-patched', mitigations: ['memory-limit-unlimited', 'upload-progress-disabled'], workersRestarted: true }));
    expect(a.state).toBe('mitigation-detected');
    expect(a.rationale.join(' ')).toMatch(/NOT shown to be patched/);
    expect(a.owner?.provenance).toBe('self-reported');
    expect(a.headline).toMatch(/self-reported/);
  });

  it('a rejected report never changes the passive state', async () => {
    const a = await withOwner('{bad json');
    expect(a.state).toBe('potentially-exposed');
    expect(a.ownerErrors.length).toBe(1);
  });
});
