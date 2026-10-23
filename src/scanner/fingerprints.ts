import type { Evidence, ResponseSnapshot } from '../shared/types';

export interface PhpVersionObservation {
  raw: string;
  header: 'x-powered-by' | 'server';
}

export interface FingerprintResult {
  evidence: Evidence[];
  phpVersions: PhpVersionObservation[];
  phpPresent: boolean;
  proxyDetected: boolean;
  distroDetected: boolean;
}

const PHP_TOKEN = /\bPHP\/(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?[^\s;,)]*)/gi;
const DISTRO_IN_SERVER = /\((Ubuntu|Debian|Red Hat[^)]*|CentOS[^)]*|Rocky[^)]*|AlmaLinux|Fedora|Amazon[^)]*|SUSE[^)]*|Alpine)\)/i;

interface ProxyRule {
  name: string;
  test: (h: Record<string, string>) => string | null;
}

const PROXY_RULES: ProxyRule[] = [
  { name: 'Cloudflare', test: (h) => (h['cf-ray'] ? `cf-ray: ${h['cf-ray']}` : /^cloudflare$/i.test(h['server'] ?? '') ? 'server: cloudflare' : null) },
  { name: 'Amazon CloudFront', test: (h) => (h['x-amz-cf-id'] ? 'x-amz-cf-id present' : /cloudfront/i.test(h['via'] ?? '') ? `via: ${h['via']}` : null) },
  { name: 'Fastly', test: (h) => (h['x-served-by'] && /cache-/i.test(h['x-served-by']) ? `x-served-by: ${h['x-served-by']}` : null) },
  { name: 'Vercel', test: (h) => (h['x-vercel-id'] ? 'x-vercel-id present' : null) },
  { name: 'Azure Front Door', test: (h) => (h['x-azure-ref'] ? 'x-azure-ref present' : null) },
  { name: 'Sucuri', test: (h) => (h['x-sucuri-id'] ? 'x-sucuri-id present' : null) },
  { name: 'Imperva', test: (h) => (h['x-iinfo'] ? 'x-iinfo present' : null) },
  { name: 'Akamai', test: (h) => (/akamai/i.test(h['server'] ?? '') ? `server: ${h['server']}` : h['x-akamai-transformed'] ? 'x-akamai-transformed present' : null) },
  { name: 'Varnish', test: (h) => (h['x-varnish'] ? 'x-varnish present' : null) },
];

interface AppRule {
  app: string;
  test: (h: Record<string, string>) => { header: string; value: string } | null;
}

const APP_RULES: AppRule[] = [
  {
    app: 'WordPress',
    test: (h) =>
      h['link'] && /rel="?https:\/\/api\.w\.org\/"?/i.test(h['link'])
        ? { header: 'link', value: h['link'] }
        : h['x-redirect-by'] && /wordpress/i.test(h['x-redirect-by'])
          ? { header: 'x-redirect-by', value: h['x-redirect-by'] }
          : h['x-pingback']
            ? { header: 'x-pingback', value: h['x-pingback'] }
            : null,
  },
  {
    app: 'Drupal',
    test: (h) =>
      h['x-generator'] && /drupal/i.test(h['x-generator'])
        ? { header: 'x-generator', value: h['x-generator'] }
        : h['x-drupal-cache'] || h['x-drupal-dynamic-cache']
          ? { header: h['x-drupal-cache'] ? 'x-drupal-cache' : 'x-drupal-dynamic-cache', value: h['x-drupal-cache'] ?? h['x-drupal-dynamic-cache'] ?? '' }
          : null,
  },
  { app: 'Magento', test: (h) => (h['x-magento-cache-debug'] ? { header: 'x-magento-cache-debug', value: h['x-magento-cache-debug'] } : null) },
];

export function fingerprint(snap: ResponseSnapshot, origin: string): FingerprintResult {
  const h = snap.headers;
  const evidence: Evidence[] = [];
  const phpVersions: PhpVersionObservation[] = [];
  let n = 0;
  const id = (p: string): string => `${p}-${++n}`;
  const src = (name: string): Evidence['source'] => ({ type: 'http-response-header', name, origin });

  const proxies = PROXY_RULES.map((r) => ({ name: r.name, hit: r.test(h) })).filter((p): p is { name: string; hit: string } => p.hit !== null);
  const proxyDetected = proxies.length > 0;

  for (const header of ['x-powered-by', 'server'] as const) {
    const value = h[header];
    if (!value) continue;
    for (const m of value.matchAll(PHP_TOKEN)) {
      const raw = m[1] ?? '';
      phpVersions.push({ raw, header });
      evidence.push({
        id: id('php-version'),
        kind: 'php-version',
        summary: `PHP version "${raw}" disclosed in the ${header} response header`,
        value: `${header}: ${value}`,
        source: src(header),
        collectedAt: snap.collectedAt,
        directness: 'direct',
        versionProvenance: 'observed',
        reliability: proxyDetected ? 'low' : 'medium',
        reliabilityReason: proxyDetected
          ? 'A CDN/reverse proxy is present: the header may come from one of several origin nodes, a cache, or be rewritten.'
          : 'Headers are set by whoever runs the server; they can be stale, spoofed, or differ between nodes. Never "high" for passive evidence.',
        doesNotProve: [
          'That every backend node runs this version',
          'That no vendor backport is installed',
          'That the running PHP workers match the installed package',
        ],
      });
    }
  }

  const xpb = h['x-powered-by'];
  const phpNoVersion = !!xpb && /\bPHP\b/i.test(xpb) && phpVersions.every((v) => v.header !== 'x-powered-by');
  if (phpNoVersion) {
    evidence.push({
      id: id('php-presence'),
      kind: 'php-presence',
      summary: 'PHP is named in x-powered-by but no version is disclosed',
      value: `x-powered-by: ${xpb}`,
      source: src('x-powered-by'),
      collectedAt: snap.collectedAt,
      directness: 'direct',
      reliability: 'medium',
      reliabilityReason: 'An explicit self-declaration by the server, but it carries no version.',
      doesNotProve: ['Which PHP version or patch level is running'],
    });
  }

  const apps: string[] = [];
  for (const rule of APP_RULES) {
    const hit = rule.test(h);
    if (!hit) continue;
    apps.push(rule.app);
    evidence.push({
      id: id('app-fingerprint'),
      kind: 'app-fingerprint',
      summary: `${rule.app} fingerprint in the ${hit.header} header (implies PHP, version unknown)`,
      value: `${hit.header}: ${hit.value}`,
      source: src(hit.header),
      collectedAt: snap.collectedAt,
      directness: 'inference',
      versionProvenance: 'inferred',
      reliability: 'low',
      reliabilityReason: 'Inferred from application-specific headers; it indicates the application stack, not the PHP version or patch state.',
      doesNotProve: ['The PHP version', 'That the application runs on an affected PHP release'],
    });
  }

  for (const p of proxies) {
    evidence.push({
      id: id('proxy-cdn'),
      kind: 'proxy-cdn',
      summary: `${p.name} (CDN / reverse proxy / WAF) detected in front of the site`,
      value: p.hit,
      source: src('response-headers'),
      collectedAt: snap.collectedAt,
      directness: 'direct',
      reliability: 'medium',
      reliabilityReason: 'Edge-specific header observed.',
      doesNotProve: [
        'What software or version runs on the origin server',
        'That the edge provides any protection against these CVEs (a WAF is risk reduction, not a patch)',
      ],
    });
  }

  const server = h['server'] ?? '';
  const distroMatch = DISTRO_IN_SERVER.exec(server);
  const suffixDistro = phpVersions.some((v) => /ubuntu|deb\d|debian|\.el\d|\.fc\d|\.amzn|remi|~/i.test(v.raw));
  const distroDetected = !!distroMatch || suffixDistro;
  if (distroDetected) {
    evidence.push({
      id: id('distro-marker'),
      kind: 'distro-marker',
      summary: distroMatch
        ? `Server header names a Linux distribution (${distroMatch[1]})`
        : 'The PHP version string carries a distribution package suffix',
      value: distroMatch ? `server: ${server}` : phpVersions.map((v) => v.raw).join(', '),
      source: src(distroMatch ? 'server' : 'x-powered-by/server'),
      collectedAt: snap.collectedAt,
      directness: 'direct',
      reliability: 'medium',
      reliabilityReason: 'Distributions commonly keep the upstream version string while backporting security fixes.',
      doesNotProve: ['Whether the distribution has shipped (or you have installed) a fix for these CVEs'],
    });
  }

  return {
    evidence,
    phpVersions,
    phpPresent: phpVersions.length > 0 || phpNoVersion || apps.length > 0,
    proxyDetected,
    distroDetected,
  };
}
