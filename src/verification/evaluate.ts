import { classifyVersion, primaryAdvisory, type AdvisoryStatus, type Classification } from '../advisories';
import { parsePhpVersion } from '../advisories/version';
import { ownerReportSchema, type OwnerReport } from './schema';
import { verifySignature } from './signature';

export const MAX_REPORT_AGE_DAYS = 30;
const MAX_FUTURE_SKEW_MS = 5 * 60_000;

export type SignatureState = 'none' | 'valid-trusted' | 'valid-untrusted' | 'unverifiable';

export type OwnerOutcome =
  | { accepted: false; errors: string[] }
  | {
      accepted: true;
      report: OwnerReport;
      signature: { state: SignatureState; keyId?: string };
      provenance: 'self-reported' | 'attested';
      classification: Classification | null;
      ageDays: number;
      patchVerificationBlockers: string[];
      claimsPatched: boolean;
      warnings: string[];
    };

// A valid signature shows a key holder signed these bytes, not that the content is true. A report counts
// as attested only if the user added that key to their trusted list.
export async function evaluateOwnerReport(
  json: string,
  ctx: { assessedOrigin: string; advisory: AdvisoryStatus; trustedKeyIds: ReadonlySet<string>; now: Date },
): Promise<OwnerOutcome> {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    return { accepted: false, errors: ['The file is not valid JSON.'] };
  }
  const parsed = ownerReportSchema.safeParse(data);
  if (!parsed.success) {
    return { accepted: false, errors: parsed.error.issues.slice(0, 5).map((i) => `${i.path.join('.') || 'report'}: ${i.message}`) };
  }
  const report = parsed.data;

  const sigCheck = await verifySignature(report);
  if (sigCheck.status === 'invalid') {
    return { accepted: false, errors: [`Invalid signature: ${sigCheck.reason} The report was rejected, not downgraded.`] };
  }

  let reportOrigin: string;
  try {
    reportOrigin = new URL(report.target.origin).origin;
  } catch {
    return { accepted: false, errors: ['target.origin is not a valid origin.'] };
  }
  if (reportOrigin !== ctx.assessedOrigin) {
    return { accepted: false, errors: [`The report is for ${reportOrigin}, not the assessed origin ${ctx.assessedOrigin}.`] };
  }

  const warnings: string[] = [];
  const blockers: string[] = [];
  const verifiedMs = Date.parse(report.verifiedAt);
  if (verifiedMs - ctx.now.getTime() > MAX_FUTURE_SKEW_MS) {
    return { accepted: false, errors: ['verifiedAt is in the future.'] };
  }
  const ageDays = Math.floor((ctx.now.getTime() - verifiedMs) / 86_400_000);
  if (ageDays > MAX_REPORT_AGE_DAYS) blockers.push(`The report is ${ageDays} days old (limit ${MAX_REPORT_AGE_DAYS}); re-verify.`);

  let signatureState: SignatureState = 'none';
  let keyId: string | undefined;
  if (sigCheck.status === 'valid') {
    keyId = sigCheck.keyId;
    signatureState = ctx.trustedKeyIds.has(sigCheck.keyId) ? 'valid-trusted' : 'valid-untrusted';
    if (signatureState === 'valid-untrusted') {
      blockers.push('The signature is valid but the signing key is not in your trusted keys.');
    }
  } else if (sigCheck.status === 'unverifiable') {
    signatureState = 'unverifiable';
    blockers.push(sigCheck.reason);
  } else {
    blockers.push('The report is unsigned, so it is self-reported and cannot be independently attributed.');
  }

  const adv = primaryAdvisory(ctx.advisory);
  const pv = parsePhpVersion(report.runtime.phpVersion);
  const classification = adv && pv ? classifyVersion(pv, adv) : null;
  const status = report.patch.status;
  const claimsPatched = status === 'fixed-upstream' || status === 'vendor-backport-applied';

  if (claimsPatched) {
    if (!report.patch.workersRestarted) blockers.push('The report does not confirm PHP workers were restarted after patching.');
    if (!adv) blockers.push('Advisory data is unavailable, so the claim cannot be checked against fixed releases.');
    if (status === 'fixed-upstream') {
      if (classification && classification.cls !== 'fixed-upstream' && classification.cls !== 'newer-than-advisory') {
        blockers.push(
          `Inconsistent: status "fixed-upstream" but PHP ${report.runtime.phpVersion} is not at or above a fixed release (${classification.explanation})`,
        );
      }
      if (report.packageSource.type === 'distro-package' || report.packageSource.type === 'vendor-image') {
        warnings.push('A distribution/vendor package normally reports "vendor-backport-applied" unless its version is itself a fixed upstream version.');
      }
    }
    if (status === 'vendor-backport-applied') {
      if (!report.vendorAdvisoryRef) blockers.push('vendor-backport-applied requires a vendorAdvisoryRef URL.');
      if (!report.packageSource.name) blockers.push('vendor-backport-applied requires packageSource.name.');
      if (!report.runtime.packageVersion) blockers.push('vendor-backport-applied requires runtime.packageVersion.');
    }
  }

  return {
    accepted: true,
    report,
    signature: { state: signatureState, ...(keyId ? { keyId } : {}) },
    provenance: signatureState === 'valid-trusted' ? 'attested' : 'self-reported',
    classification,
    ageDays,
    patchVerificationBlockers: claimsPatched ? blockers : ['The report does not claim the host is patched.'],
    claimsPatched,
    warnings,
  };
}
