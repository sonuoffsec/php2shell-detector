// Post-build audit of the RELEASE bundle (dist/). Exits non-zero on any violation.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const fail = [];
const dist = 'dist';
const built = JSON.parse(readFileSync(join(dist, 'manifest.json'), 'utf8'));
const source = JSON.parse(readFileSync('extension/static/manifest.json', 'utf8'));

if (JSON.stringify(built) !== JSON.stringify(source)) fail.push('dist/manifest.json differs from extension/static/manifest.json');
if (JSON.stringify(built.host_permissions) !== '["http://*/*","https://*/*"]') fail.push(`unexpected host_permissions: ${built.host_permissions}`);
if (built.optional_host_permissions) fail.push('unexpected optional_host_permissions');
if (built.key) fail.push('release manifest must not contain a "key"');
if (JSON.stringify([...built.permissions].sort()) !== '["activeTab","storage"]') fail.push(`unexpected permissions: ${built.permissions}`);

// Every absolute URL baked into shipped JS/HTML must be an allowed documentation/reference/namespace host.
const allowed = [
  'www.php.net', 'github.com', 'cloud.google.com', 'www.wiz.io', // advisory reference links (opened only on click)
  'www.w3.org', // SVG/XML namespaces
  'reactjs.org', 'react.dev', 'legacy.reactjs.org', // React error-message links (strings, never fetched)
  'ubuntu.com', 'example.com', 'api.w.org', // examples / header fingerprint strings
];
const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));
for (const f of walk(dist).filter((p) => /\.(js|html|css)$/.test(p))) {
  const text = readFileSync(f, 'utf8');
  for (const m of text.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) {
    const host = m[1].toLowerCase();
    if (!allowed.some((a) => host === a || host.endsWith(`.${a}`))) fail.push(`${f}: unexpected host ${host}`);
  }
  if (/<script[^>]+src=["']https?:/i.test(text)) fail.push(`${f}: remote script`);
}

if (fail.length) {
  console.error('check-dist FAILED:\n- ' + fail.join('\n- '));
  process.exit(1);
}
console.log('check-dist OK: release manifest unchanged, permissions = activeTab+storage + http(s) host access, no unexpected hosts, no remote scripts.');
