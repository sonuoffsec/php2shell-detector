export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number | null;
  suffix: string;
  prerelease: boolean;
  distroSuffix: boolean;
}

const DISTRO_SUFFIX = /(ubuntu|deb\d*|debian|\.el\d|\.fc\d|\.amzn|\.rhel|alpine|remi|\.sles?|\.suse|bpo\d|~|\+dfsg|-\d+\+)/i;

export function parsePhpVersion(raw: string): ParsedVersion | null {
  const m = /^(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?(.*)$/.exec(raw.trim());
  if (!m) return null;
  const suffix = m[4] ?? '';
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: m[3] === undefined ? null : Number(m[3]),
    suffix,
    prerelease: /^[-~.]?(alpha|beta|rc|dev)/i.test(suffix),
    distroSuffix: DISTRO_SUFFIX.test(suffix),
  };
}

export const branchOf = (v: ParsedVersion): string => `${v.major}.${v.minor}`;

export function cmpBranch(a: string, b: string): number {
  const [am = 0, an = 0] = a.split('.').map(Number);
  const [bm = 0, bn = 0] = b.split('.').map(Number);
  return am !== bm ? am - bm : an - bn;
}

export function compareToRelease(v: ParsedVersion, target: string): number {
  const [tM = 0, tm = 0, tp = 0] = target.split('.').map(Number);
  if (v.major !== tM) return v.major - tM;
  if (v.minor !== tm) return v.minor - tm;
  const p = v.patch ?? 0;
  if (p !== tp) return p - tp;
  return v.prerelease ? -1 : 0;
}
