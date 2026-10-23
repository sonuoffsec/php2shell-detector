import raw from './data/php2shell.json';
import { advisoryDatasetSchema, type Advisory, type AdvisoryDataset } from './schema';
import { branchOf, cmpBranch, compareToRelease, type ParsedVersion } from './version';

export type AdvisoryStatus =
  | { available: true; dataset: AdvisoryDataset; stale: boolean; ageDays: number; verifiedAt: string }
  | { available: false; reason: string };

export function loadAdvisories(data: unknown, now: Date): AdvisoryStatus {
  const parsed = advisoryDatasetSchema.safeParse(data);
  if (!parsed.success) {
    return { available: false, reason: `Advisory data failed validation: ${parsed.error.issues[0]?.message ?? 'unknown error'}` };
  }
  const verified = new Date(parsed.data.dataset.lastVerifiedAt);
  const ageDays = Math.floor((now.getTime() - verified.getTime()) / 86_400_000);
  return {
    available: true,
    dataset: parsed.data,
    stale: ageDays > parsed.data.dataset.maxAgeDays || ageDays < 0,
    ageDays,
    verifiedAt: parsed.data.dataset.lastVerifiedAt,
  };
}

export const loadBundledAdvisories = (now: Date = new Date()): AdvisoryStatus => loadAdvisories(raw, now);

export type VersionClass =
  | 'affected-upstream'
  | 'fixed-upstream'
  | 'unsupported-branch'
  | 'below-advisory-scope'
  | 'newer-than-advisory'
  | 'branch-only';

export interface Classification {
  cls: VersionClass;
  branch: string;
  fixedIn: string | null;
  explanation: string;
}

export function classifyVersion(v: ParsedVersion, adv: Advisory): Classification {
  const branch = branchOf(v);
  const supported = adv.scope.supportedBranches.find((b) => b.branch === branch);
  if (supported) {
    if (v.patch === null) {
      return { cls: 'branch-only', branch, fixedIn: supported.fixedIn, explanation: `Only the branch ${branch} was disclosed; the fix is ${supported.fixedIn}.` };
    }
    const affected = compareToRelease(v, supported.fixedIn) < 0;
    return {
      cls: affected ? 'affected-upstream' : 'fixed-upstream',
      branch,
      fixedIn: supported.fixedIn,
      explanation: affected
        ? `${branch} branch releases before ${supported.fixedIn} are affected upstream.`
        : `${supported.fixedIn} is the first fixed release on the ${branch} branch.`,
    };
  }
  const newest = adv.scope.supportedBranches.map((b) => b.branch).sort(cmpBranch).at(-1) ?? branch;
  if (cmpBranch(branch, newest) > 0) {
    return { cls: 'newer-than-advisory', branch, fixedIn: null, explanation: `Branch ${branch} is newer than the newest branch (${newest}) covered by the advisory.` };
  }
  if (cmpBranch(branch, adv.scope.earliestAffectedBranch) < 0) {
    return { cls: 'below-advisory-scope', branch, fixedIn: null, explanation: `Branch ${branch} is older than ${adv.scope.earliestAffectedBranch}, the oldest branch any source lists as affected; it is outside the advisory's scope but long unsupported.` };
  }
  return { cls: 'unsupported-branch', branch, fixedIn: null, explanation: `Branch ${branch} has no upstream release containing the fix. Sources disagree on whether source-only backports exist.` };
}

export const primaryAdvisory = (s: AdvisoryStatus): Advisory | null => (s.available ? (s.dataset.advisories[0] ?? null) : null);
