import { redactDeep } from '../privacy/redact';
import type { Assessment } from '../assessment/engine';
import { STATE_LABELS } from '../shared/types';

export const REPORT_SCHEMA = 'php2shell-detector/assessment-report';
export const TOOL_VERSION = '0.1.0';

// Excluded on purpose: cookies, credentials, authorization headers, bodies, full header sets, URL paths.
export function buildJsonReport(a: Assessment, generatedAt: Date = new Date()): Record<string, unknown> {
  const report = {
    schema: REPORT_SCHEMA,
    schemaVersion: 1,
    tool: { name: 'PHP2Shell Detector', version: TOOL_VERSION },
    generatedAt: generatedAt.toISOString(),
    target: {
      requestedOrigin: a.target.requestedOrigin,
      finalOrigin: a.target.finalOrigin,
      redirected: a.target.redirected,
      hostChanged: a.target.hostChanged,
    },
    assessedAt: a.assessedAt,
    assessment: {
      state: a.state,
      label: STATE_LABELS[a.state],
      headline: a.headline,
      ruleId: a.ruleId,
      rationale: a.rationale,
    },
    confidence: { level: a.confidence.level, basis: a.confidence.basis, note: 'Qualitative label, not a probability. See docs/METHODOLOGY.md.' },
    evidence: a.evidence.map((e) => ({
      id: e.id,
      kind: e.kind,
      summary: e.summary,
      observed: e.value,
      source: e.source,
      collectedAt: e.collectedAt,
      directness: e.directness,
      versionProvenance: e.versionProvenance ?? null,
      reliability: e.reliability,
      reliabilityReason: e.reliabilityReason,
      doesNotProve: e.doesNotProve,
    })),
    cves: a.cves,
    fixedUpstreamReleases: a.fixedReleases,
    advisoryData: a.advisory,
    ownerVerification: a.owner,
    ownerReportErrors: a.ownerErrors,
    unverifiedAssumptions: a.unknowns,
    warnings: a.warnings,
    recommendedActions: a.nextSteps.map((s) => ({ title: s.title, detail: s.detail })),
    references: a.references.map((r) => ({ title: r.title, publisher: r.publisher, url: r.url, checkedAt: r.checkedAt })),
    disclaimer:
      'Generated from passive public-response evidence and optional owner-supplied data. It is not proof that a server is vulnerable or safe.',
  };
  return redactDeep(report);
}
