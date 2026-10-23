// Headers are allowlisted when collected, so anything not needed for fingerprinting is never stored.
// The denylist is a second check for exports and free text.

export const HEADER_ALLOWLIST: ReadonlySet<string> = new Set([
  'server',
  'x-powered-by',
  'via',
  'x-generator',
  'x-pingback',
  'x-redirect-by',
  'x-drupal-cache',
  'x-drupal-dynamic-cache',
  'x-magento-cache-debug',
  'link',
  'cf-ray',
  'x-amz-cf-id',
  'x-amz-cf-pop',
  'x-served-by',
  'x-vercel-id',
  'x-azure-ref',
  'x-sucuri-id',
  'x-iinfo',
  'x-akamai-transformed',
  'x-cache',
  'x-varnish',
]);

export const SENSITIVE_HEADERS: ReadonlySet<string> = new Set([
  'set-cookie',
  'cookie',
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
  'www-authenticate',
]);

export const REDACTED = '[REDACTED]';

const MAX_VALUE_LENGTH = 200;

export function scrubValue(value: string): string {
  let v = value.replace(/(https?:\/\/[^\s<>"',;]+?)[?#][^\s<>"',;]*/g, '$1');
  v = v.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, `$1 ${REDACTED}`);
  v = v.replace(/\b[A-Fa-f0-9]{32,}\b/g, REDACTED);
  v = v.replace(/\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)/g, REDACTED);
  v = v.replace(/https?:\/\/[^\s/@]+:[^\s/@]+@/g, 'https://');
  return v.length > MAX_VALUE_LENGTH ? `${v.slice(0, MAX_VALUE_LENGTH)}…` : v;
}

export function minimizeHeaders(entries: Iterable<[string, string]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [rawName, value] of entries) {
    const name = rawName.toLowerCase();
    if (SENSITIVE_HEADERS.has(name)) {
      out[name] = REDACTED;
    } else if (HEADER_ALLOWLIST.has(name)) {
      out[name] = scrubValue(value);
    }
  }
  return out;
}

export function redactDeep<T>(input: T): T {
  const walk = (v: unknown, key?: string): unknown => {
    if (key && SENSITIVE_HEADERS.has(key.toLowerCase())) return REDACTED;
    if (typeof v === 'string') return scrubValue(v);
    if (Array.isArray(v)) return v.map((x) => walk(x));
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, k)]));
    }
    return v;
  };
  return walk(input) as T;
}
