import { classifyVersion, primaryAdvisory, type AdvisoryStatus, type Classification } from '../advisories';
import { parsePhpVersion, type ParsedVersion } from '../advisories/version';
import type { CollectResult } from '../scanner/collect';
import { fingerprint } from '../scanner/fingerprints';
import { buildTargetInfo } from '../scanner/target';
import type { OwnerOutcome } from '../verification/evaluate';
import type { AssessmentState, Evidence, NextStep, Reference, TargetInfo } from '../shared/types';
import { buildNextSteps } from './guidance';

export type ConfidenceLevel = 'low' | 'medium' | 'high';

export interface Assessment {
  state: AssessmentState;
  headline: string;
  rationale: string[];
  ruleId: string;
  ruleTrace: string[];
  target: TargetInfo;
  assessedAt: string;
  evidence: Evidence[];
  cves: { id: string; ghsa?: string | undefined; summary: string }[];
  fixedReleases: { branch: string; fixedIn: string }[];
  advisory: { available: boolean; datasetId?: string; verifiedAt?: string; stale: boolean; ageDays?: number; note?: string };
  unknowns: string[];
  warnings: string[];
  nextSteps: NextStep[];
  confidence: { level: ConfidenceLevel; basis: string[] };
  owner:
    | null
    | {
        provenance: 'self-reported' | 'attested';
        signature: string;
        phpVersion: string;
        patchStatus: string;
        verifiedAt: string;
        workersRestarted: boolean;
        credited: boolean;
        blockers: string[];
      };
  ownerErrors: string[];
  references: Reference[];
}

export interface AssessInput {
  requestedOrigin: string;
  collect: CollectResult;
  advisory: AdvisoryStatus;
  owner?: OwnerOutcome | null;
  now?: Date;
}

interface Passive {
  state: AssessmentState;
  ruleId: string;
  headline: string;
  rationale: string[];
}

const baseNumeric = (v: ParsedVersion): string => `${v.major}.${v.minor}.${v.patch ?? 'x'}`;

export function assess(input: AssessInput): Assessment {
  const now = input.now ?? new Date();
  const assessedAt = now.toISOString();
  const trace: string[] = [];
  const warnings: string[] = [];
  const unknowns: string[] = [
    'Whether the origin server actually runs the PHP version a header discloses.',
    'Whether a distribution or vendor backport is installed.',
    'Whether all PHP workers were restarted after any update.',
    'Which backend node served this response when multiple nodes exist.',
  ];

  const adv = primaryAdvisory(input.advisory);
  const advStale = input.advisory.available ? input.advisory.stale : false;

  let evidence: Evidence[] = [];
  let target: TargetInfo;
  let phpVersionsRaw: string[] = [];
  let proxy = false;
  let distro = false;
  let phpPresent = false;
  let status: number | null = null;

  if (!input.collect.ok) {
    target = buildTargetInfo(input.requestedOrigin, null, false);
    evidence.push({
      id: 'fetch-error-1',
      kind: 'fetch-error',
      summary: 'The request to the target failed',
      value: input.collect.error,
      source: { type: 'network', name: 'GET /', origin: input.requestedOrigin },
      collectedAt: assessedAt,
      directness: 'direct',
      reliability: 'high',
      reliabilityReason: 'Observed locally by the browser.',
      doesNotProve: ['Anything about the PHP version or patch state'],
    });
  } else {
    const snap = input.collect.snapshot;
    target = buildTargetInfo(input.requestedOrigin, snap.finalUrlOrigin, input.collect.redirected);
    status = snap.status;
    const fp = fingerprint(snap, snap.finalUrlOrigin);
    evidence = fp.evidence;
    phpVersionsRaw = [...new Set(fp.phpVersions.map((v) => v.raw))];
    proxy = fp.proxyDetected;
    distro = fp.distroDetected;
    phpPresent = fp.phpPresent;
    evidence.unshift({
      id: 'http-status-1',
      kind: 'http-status',
      summary: `HTTP ${snap.status} received from ${snap.finalUrlOrigin}/`,
      value: String(snap.status),
      source: { type: 'http-response', name: 'status', origin: snap.finalUrlOrigin },
      collectedAt: snap.collectedAt,
      directness: 'direct',
      reliability: 'high',
      reliabilityReason: 'Observed locally by the browser.',
      doesNotProve: ['That other paths, vhosts or backend nodes behave the same'],
    });
    if (target.redirected) {
      evidence.push({
        id: 'redirect-1',
        kind: 'redirect',
        summary: target.hostChanged
          ? `Redirected from ${target.requestedHost} to a different host (${target.finalHost})`
          : `Redirected within ${target.requestedHost} (${target.requestedOrigin} → ${target.finalOrigin})`,
        value: `${target.requestedOrigin} → ${target.finalOrigin}`,
        source: { type: 'http-response', name: 'redirect', origin: target.requestedOrigin },
        collectedAt: snap.collectedAt,
        directness: 'direct',
        reliability: 'high',
        reliabilityReason: 'Observed locally by the browser.',
        doesNotProve: ['That the requested host and the final host share a backend'],
      });
    }
  }

  const parsedVersions = phpVersionsRaw
    .map((raw) => ({ raw, parsed: parsePhpVersion(raw) }))
    .filter((v): v is { raw: string; parsed: ParsedVersion } => v.parsed !== null);
  let classification: Classification | null = null;
  const passive = ((): Passive => {
    if (!input.collect.ok) {
      trace.push('R01 fetch failed');
      return {
        state: 'inconclusive',
        ruleId: 'R01-FETCH-FAILED',
        headline: 'The site could not be assessed',
        rationale: [input.collect.error, 'No evidence was collected, so nothing can be said about PHP2Shell exposure.'],
      };
    }
    if (target.hostChanged) {
      trace.push('R02 redirect changed host');
      unknowns.push(`Evidence was collected from ${target.finalHost}, which is not the host you asked about (${target.requestedHost}).`);
      return {
        state: 'inconclusive',
        ruleId: 'R02-REDIRECT-HOST',
        headline: 'The request ended on a different host',
        rationale: [
          `${target.requestedOrigin} redirected to ${target.finalOrigin}. Headers observed there describe that host, not the one you requested.`,
          'To assess the destination, enter it as a separate target. It is not assessed automatically.',
        ],
      };
    }
    if (target.originChanged) {
      trace.push('R03 redirect same host, scheme/port changed');
      warnings.push(`Redirected from ${target.requestedOrigin} to ${target.finalOrigin} (same host, different scheme or port). Evidence is from the final origin.`);
    }

    const distinct = new Set(parsedVersions.map((v) => v.raw));
    const distinctBase = new Set(parsedVersions.map((v) => baseNumeric(v.parsed)));
    if (distinctBase.size > 1) {
      trace.push('R04 conflicting versions');
      return {
        state: 'inconclusive',
        ruleId: 'R04-CONFLICT',
        headline: 'Evidence conflicts',
        rationale: [
          `Different PHP versions were disclosed in different headers (${[...distinct].join(' vs ')}).`,
          'One of the values is stale, spoofed, or from a different layer. No version is credited.',
        ],
      };
    }
    if (parsedVersions.length === 0 && phpVersionsRaw.length > 0) {
      trace.push('R05 unparseable version');
      return {
        state: 'inconclusive',
        ruleId: 'R05-UNPARSEABLE',
        headline: 'A PHP version string was present but could not be parsed',
        rationale: [`Value: ${phpVersionsRaw.join(', ')}`],
      };
    }

    const first = parsedVersions[0];
    if (first) {
      if (!adv) {
        trace.push('R06 advisory unavailable');
        return {
          state: 'inconclusive',
          ruleId: 'R06-ADVISORY-UNAVAILABLE',
          headline: 'A PHP version was observed but advisory data is unavailable',
          rationale: [
            `PHP ${first.raw} was disclosed, but ${input.advisory.available ? 'no advisory is loaded' : input.advisory.reason}.`,
            'Without validated advisory data no version comparison is made.',
          ],
        };
      }
      classification = classifyVersion(first.parsed, adv);
      trace.push(`R07 classify ${first.raw} → ${classification.cls}`);
      const v = `PHP ${first.raw}`;
      const proxyNote = proxy ? ['A CDN/reverse proxy was detected; the header may not describe every origin node.'] : [];
      switch (classification.cls) {
        case 'affected-upstream':
          if (distro) {
            return {
              state: 'exposure-indicators',
              ruleId: 'R10-AFFECTED-BACKPORT-POSSIBLE',
              headline: 'Affected upstream version string, but a vendor backport may apply',
              rationale: [
                `${v} is below the fixed upstream release ${classification.fixedIn}, but the string/headers carry a distribution marker.`,
                'Distributions often backport fixes without changing the PHP version, so this does not establish vulnerability.',
                ...proxyNote,
              ],
            };
          }
          if (advStale) warnings.push('Advisory data is stale: re-verify the fixed-release list before relying on this result.');
          return {
            state: 'potentially-exposed',
            ruleId: 'R08-AFFECTED-UPSTREAM',
            headline: 'Disclosed PHP version is below the fixed upstream release',
            rationale: [
              `${v} was disclosed in a response header. ${classification.explanation}`,
              'No distribution marker was seen, but a custom or vendor backport cannot be ruled out from outside.',
              'Patch status has not been verified.',
              ...proxyNote,
            ],
          };
        case 'unsupported-branch':
          return {
            state: distro ? 'exposure-indicators' : 'potentially-exposed',
            ruleId: distro ? 'R11-UNSUPPORTED-BACKPORT-POSSIBLE' : 'R09-UNSUPPORTED-BRANCH',
            headline: distro ? 'Unsupported PHP branch; a vendor backport may apply' : 'Unsupported PHP branch with no upstream fixed release',
            rationale: [
              `${v} is on the ${classification.branch} branch. ${classification.explanation}`,
              distro
                ? 'A distribution marker is present, so a vendor-maintained backport may exist; verify with the vendor.'
                : 'Without a vendor-maintained build this runtime is likely unpatched.',
              ...proxyNote,
            ],
          };
        case 'branch-only':
          return {
            state: 'exposure-indicators',
            ruleId: 'R12-BRANCH-ONLY',
            headline: 'Only the PHP branch is disclosed',
            rationale: [`${v}: ${classification.explanation}`, 'The patch level is unknown, so this cannot be classified as affected or fixed.', ...proxyNote],
          };
        case 'below-advisory-scope':
          return {
            state: 'exposure-indicators',
            ruleId: 'R13-BELOW-SCOPE',
            headline: 'Very old PHP branch outside the advisory’s stated range',
            rationale: [`${v}: ${classification.explanation}`, 'Treat as an unsupported runtime and confirm with the administrator.', ...proxyNote],
          };
        case 'fixed-upstream':
        case 'newer-than-advisory':
          if (advStale || !input.advisory.available) {
            return {
              state: 'inconclusive',
              ruleId: 'R15-FIXED-BUT-STALE',
              headline: 'Disclosed version looks fixed, but advisory data is stale',
              rationale: [`${v} is at or above the listed fixed release, but the bundled advisory data is ${input.advisory.available ? `${input.advisory.ageDays} days old` : 'unavailable'}. Re-verify before relying on this.`],
            };
          }
          if (parsedVersions.some((p) => p.parsed.prerelease)) warnings.push('A pre-release version string was disclosed.');
          return {
            state: 'no-indicators',
            ruleId: 'R14-FIXED-DISCLOSED',
            headline: 'No exposure indicators: disclosed version is at or above the fixed release',
            rationale: [
              `${v} was disclosed. ${classification.explanation}`,
              'This is not patch verification: a header is trivially spoofable or stale, and other backend nodes or workers may differ.',
              ...proxyNote,
            ],
          };
      }
    }

    if (phpPresent) {
      trace.push('R16 PHP present, version hidden');
      return {
        state: 'exposure-indicators',
        ruleId: 'R16-PHP-NO-VERSION',
        headline: 'PHP is likely in use but its version is hidden',
        rationale: [
          'Technology indicators suggest a PHP application stack, but no PHP version was disclosed.',
          'A missing version is not a guess: patch level is unknown. Use owner verification to establish it.',
        ],
      };
    }
    if (status !== null && (status >= 500 || status === 403 || status === 429)) {
      trace.push('R17 blocked/errored');
      return {
        state: 'inconclusive',
        ruleId: 'R17-HTTP-ERROR',
        headline: 'The server returned an error or blocked the request',
        rationale: [`HTTP ${status} was returned with no PHP indicators. Error and bot-protection pages often omit application headers.`],
      };
    }
    if (proxy) {
      trace.push('R18 proxy opaque');
      return {
        state: 'inconclusive',
        ruleId: 'R18-PROXY-OPAQUE',
        headline: 'A CDN or reverse proxy hides the origin',
        rationale: [
          'An edge service responded and no PHP indicator was visible through it.',
          'The origin may still run PHP; the edge typically strips or never forwards such headers.',
        ],
      };
    }
    trace.push('R19 nothing found');
    return {
      state: 'no-indicators',
      ruleId: 'R19-NONE',
      headline: 'No PHP indicators were visible',
      rationale: [
        'The response headers contained no PHP version or PHP-specific fingerprint.',
        'This does NOT establish the site is safe: PHP can run with all disclosure hidden.',
      ],
    };
  })();

  let { state, ruleId, headline } = passive;
  const rationale = [...passive.rationale];

  let owner: Assessment['owner'] = null;
  let ownerErrors: string[] = [];
  const ow = input.owner ?? null;
  if (ow && !ow.accepted) {
    ownerErrors = ow.errors;
    warnings.push('An imported owner report was rejected and had no effect on this assessment.');
  } else if (ow?.accepted) {
    const r = ow.report;
    const sigLabel =
      ow.signature.state === 'valid-trusted'
        ? `signed by trusted key ${ow.signature.keyId?.slice(0, 16)}…`
        : ow.signature.state === 'valid-untrusted'
          ? `signed by UNTRUSTED key ${ow.signature.keyId?.slice(0, 16)}…`
          : ow.signature.state === 'unverifiable'
            ? 'signature could not be verified in this browser'
            : 'unsigned';
    evidence.push({
      id: 'owner-report-1',
      kind: 'owner-report',
      summary: `Owner report: PHP ${r.runtime.phpVersion}, patch status “${r.patch.status}”, ${sigLabel}`,
      value: `verifiedAt ${r.verifiedAt}; package source ${r.packageSource.type}${r.packageSource.name ? ` (${r.packageSource.name})` : ''}; workersRestarted=${r.patch.workersRestarted}`,
      source: { type: 'owner-report', name: 'imported JSON', origin: input.requestedOrigin },
      collectedAt: assessedAt,
      directness: ow.provenance === 'attested' ? 'attested' : 'self-reported',
      versionProvenance: ow.provenance === 'attested' ? 'attested' : 'admin-supplied',
      reliability: ow.provenance === 'attested' ? 'high' : 'low',
      reliabilityReason:
        ow.provenance === 'attested'
          ? 'Signed by a key you trust. This proves who signed, not that the content is true; the signer vouches for their own server.'
          : 'Self-reported: anyone can write this file. The extension did not inspect the server.',
      doesNotProve: ['That the extension inspected the server’s PHP binary', 'That the claim is true (it is the signer’s or author’s statement)'],
    });

    const observedBases = new Set(parsedVersions.map((p) => baseNumeric(p.parsed)));
    const reportParsed = parsePhpVersion(r.runtime.phpVersion);
    const conflicts = !!reportParsed && observedBases.size > 0 && !observedBases.has(baseNumeric(reportParsed));
    if (conflicts) warnings.push(`The report says PHP ${r.runtime.phpVersion} but the public header disclosed ${[...observedBases].join(', ')}. One is stale, spoofed, or from another node.`);

    const blockers = [...ow.patchVerificationBlockers];
    let credited = false;
    if (ow.claimsPatched && blockers.length === 0) {
      if (conflicts) {
        state = 'inconclusive';
        ruleId = 'O03-OWNER-CONFLICT';
        headline = 'Owner report conflicts with public evidence';
        rationale.length = 0;
        rationale.push('A trusted, signed report claims the host is patched, but the version it reports differs from the version disclosed publicly. The conflict must be resolved before crediting either.');
        trace.push('O03 owner conflict');
      } else {
        state = 'patch-verified';
        ruleId = 'O01-PATCH-VERIFIED';
        headline = 'Patch verified by a trusted owner attestation';
        credited = true;
        rationale.length = 0;
        rationale.push(
          `A report ${sigLabel} states PHP ${r.runtime.phpVersion} is ${r.patch.status === 'fixed-upstream' ? 'a fixed upstream release' : 'carrying the vendor backport'} and workers were restarted (${r.verifiedAt}).`,
          'The signature proves who signed the report, not that it is true. The extension did not inspect the server.',
        );
        trace.push('O01 patch verified');
      }
    } else if (!ow.claimsPatched && r.patch.mitigations.length > 0 && state !== 'no-indicators') {
      state = 'mitigation-detected';
      ruleId = 'O02-MITIGATION';
      headline = `Mitigation reported by the owner (${ow.provenance === 'attested' ? 'attested' : 'self-reported'})`;
      credited = true;
      rationale.length = 0;
      rationale.push(
        `The owner reports these mitigations: ${r.patch.mitigations.join(', ')}; patch status “${r.patch.status}”.`,
        'Mitigations reduce exposure but upstream states updating is the only complete fix. The underlying PHP is NOT shown to be patched.',
        ...(r.patch.workersRestarted ? [] : ['The report does not confirm workers were restarted, so the mitigation may not be active.']),
      );
      trace.push('O02 mitigation');
    } else if (ow.claimsPatched) {
      rationale.push(`An owner report claims the host is patched, but it is not credited: ${blockers.join(' ')}`);
      trace.push('O00 claim not credited');
    }
    owner = {
      provenance: ow.provenance,
      signature: sigLabel,
      phpVersion: r.runtime.phpVersion,
      patchStatus: r.patch.status,
      verifiedAt: r.verifiedAt,
      workersRestarted: r.patch.workersRestarted,
      credited,
      blockers: ow.claimsPatched ? blockers : [],
    };
    warnings.push(...ow.warnings);
  }

  if (advStale) warnings.push(`Advisory data was last verified ${input.advisory.available ? input.advisory.verifiedAt : ''} and is considered stale.`);
  if (!input.advisory.available) warnings.push(input.advisory.reason);
  if (proxy) unknowns.push('What the CDN/proxy hides, rewrites or caches.');
  if (state === 'no-indicators') unknowns.push('Whether PHP runs behind headers that disclose nothing.');

  const basis: string[] = [];
  let level: ConfidenceLevel = 'low';
  if (state === 'patch-verified') {
    level = 'high';
    basis.push('Signed attestation from a key the user trusts, consistent with advisory data and public evidence.');
  } else if (state === 'potentially-exposed' && !proxy && !advStale && evidence.some((e) => e.kind === 'php-version' && e.reliability === 'medium')) {
    level = 'medium';
    basis.push('A direct version header, no CDN detected, fresh advisory data. Header still spoofable.');
  } else {
    basis.push(
      state === 'no-indicators'
        ? 'Absence of indicators is weak evidence by nature.'
        : state === 'inconclusive'
          ? 'Evidence is insufficient, conflicting or unreliable.'
          : 'Evidence is indirect, partly self-reported, or affected by backports/proxies.',
    );
  }
  if (!['patch-verified'].includes(state) && level !== 'medium') level = 'low';

  const unsupportedBranch = classification?.cls === 'unsupported-branch' || classification?.cls === 'below-advisory-scope';
  const nextSteps = buildNextSteps({
    distro,
    proxy,
    branch: classification?.branch ?? null,
    unsupportedBranch,
    originalOrigin: input.requestedOrigin,
  });

  return {
    state,
    headline,
    rationale,
    ruleId,
    ruleTrace: trace,
    target,
    assessedAt,
    evidence,
    cves: adv ? adv.cves.map((c) => ({ id: c.id, ghsa: c.ghsa, summary: c.summary })) : [],
    fixedReleases: adv ? adv.scope.supportedBranches.map((b) => ({ branch: b.branch, fixedIn: b.fixedIn })) : [],
    advisory: input.advisory.available
      ? { available: true, datasetId: input.advisory.dataset.dataset.id, verifiedAt: input.advisory.verifiedAt, stale: input.advisory.stale, ageDays: input.advisory.ageDays }
      : { available: false, stale: false, note: input.advisory.reason },
    unknowns: [...new Set(unknowns)],
    warnings: [...new Set(warnings)],
    nextSteps,
    confidence: { level, basis },
    owner,
    ownerErrors,
    references: input.advisory.available ? input.advisory.dataset.references : [],
  };
}
