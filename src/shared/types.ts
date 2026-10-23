
export type AssessmentState =
  | 'potentially-exposed'
  | 'exposure-indicators'
  | 'mitigation-detected'
  | 'patch-verified'
  | 'inconclusive'
  | 'no-indicators';

export const STATE_LABELS: Record<AssessmentState, string> = {
  'potentially-exposed': 'Potentially exposed',
  'exposure-indicators': 'Exposure indicators detected',
  'mitigation-detected': 'Mitigation detected',
  'patch-verified': 'Patch verified',
  inconclusive: 'Inconclusive',
  'no-indicators': 'No indicators detected',
};

export type Directness = 'direct' | 'inference' | 'self-reported' | 'attested';
export type VersionProvenance = 'observed' | 'inferred' | 'admin-supplied' | 'attested';
export type Reliability = 'low' | 'medium' | 'high';

export type EvidenceKind =
  | 'php-version'
  | 'php-presence'
  | 'distro-marker'
  | 'proxy-cdn'
  | 'app-fingerprint'
  | 'redirect'
  | 'http-status'
  | 'fetch-error'
  | 'owner-report';

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  summary: string;
  value: string;
  source: { type: 'http-response-header' | 'http-response' | 'owner-report' | 'network'; name: string; origin: string };
  collectedAt: string;
  directness: Directness;
  versionProvenance?: VersionProvenance;
  reliability: Reliability;
  reliabilityReason: string;
  doesNotProve: string[];
}

export interface TargetInfo {
  requestedOrigin: string;
  requestedHost: string;
  finalOrigin: string | null;
  finalHost: string | null;
  redirected: boolean;
  originChanged: boolean;
  hostChanged: boolean;
}

export interface ResponseSnapshot {
  status: number;
  finalUrlOrigin: string;
  headers: Record<string, string>;
  collectedAt: string;
}

export interface Reference {
  id: string;
  title: string;
  url: string;
  publisher: string;
  type: 'vendor-advisory' | 'ghsa' | 'research' | 'cloud-guidance' | 'release-archive';
  checkedAt: string;
  claims: string[];
}

export interface NextStep {
  id: string;
  title: string;
  detail: string;
}
