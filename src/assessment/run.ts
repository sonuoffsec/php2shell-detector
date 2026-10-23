import { loadBundledAdvisories, type AdvisoryStatus } from '../advisories';
import { collectSnapshot, type CollectOptions } from '../scanner/collect';
import { parseTarget } from '../scanner/target';
import { evaluateOwnerReport } from '../verification/evaluate';
import { assess, type Assessment } from './engine';

export type RunResult = { ok: true; assessment: Assessment } | { ok: false; error: string };

export interface RunDeps extends CollectOptions {
  advisory?: AdvisoryStatus;
  ownerReportJson?: string | null;
  trustedKeyIds?: ReadonlySet<string>;
}

export async function runAssessment(input: string, deps: RunDeps = {}): Promise<RunResult> {
  const target = parseTarget(input);
  if (!target.ok) return { ok: false, error: target.error };
  const now = deps.now?.() ?? new Date();
  const advisory = deps.advisory ?? loadBundledAdvisories(now);
  const collect = await collectSnapshot(target.origin, deps);
  const owner = deps.ownerReportJson
    ? await evaluateOwnerReport(deps.ownerReportJson, {
        assessedOrigin: target.origin,
        advisory,
        trustedKeyIds: deps.trustedKeyIds ?? new Set(),
        now,
      })
    : null;
  return { ok: true, assessment: assess({ requestedOrigin: target.origin, collect, advisory, owner, now }) };
}
