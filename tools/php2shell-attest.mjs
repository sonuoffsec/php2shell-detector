/*
 * Companion CLI for site administrators.
 *
 *   node tools/php2shell-attest.mjs keygen --out attest-key.json
 *   node tools/php2shell-attest.mjs report --origin https://example.com --key attest-key.json \
 *        --patch-status vendor-backport-applied --workers-restarted \
 *        --package-source distro-package --package-name "Debian php8.2" \
 *        --package-version 8.2.29-1~deb12u1 --vendor-advisory https://security-tracker.debian.org/... \
 *        --out report.json
 *
 * Reads the local php binary for version and SAPI, then signs the report with Ed25519. No network access.
 * Patch status and workers-restarted are stated by the operator; the tool cannot measure them.
 * The php CLI may not be the binary your web server uses, so use --php-bin or --php-version if unsure.
 */
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');

export function generateKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const rawPublic = publicKey.export({ format: 'jwk' }).x; // base64url raw 32-byte key
  const keyId = createHash('sha256').update(Buffer.from(rawPublic, 'base64url')).digest('hex');
  return { privateJwk: privateKey.export({ format: 'jwk' }), publicKey: rawPublic, keyId };
}

export function signReport(report, keyFile) {
  const { signature: _ignored, ...unsigned } = report;
  const priv = createPrivateKey({ key: keyFile.privateJwk, format: 'jwk' });
  const value = sign(null, Buffer.from(canonicalize(unsigned)), priv);
  return { ...unsigned, signature: { alg: 'Ed25519', keyId: keyFile.keyId, publicKey: keyFile.publicKey, value: b64url(value) } };
}

export function buildReport(opts) {
  return {
    schema: 'php2shell-detector/owner-report',
    schemaVersion: 1,
    target: { origin: new URL(opts.origin).origin },
    runtime: {
      phpVersion: opts.phpVersion,
      ...(opts.packageVersion ? { packageVersion: opts.packageVersion } : {}),
      ...(opts.sapi ? { sapi: opts.sapi } : {}),
    },
    ...(opts.osName ? { os: { name: opts.osName, ...(opts.osVersion ? { version: opts.osVersion } : {}) } } : {}),
    packageSource: { type: opts.packageSourceType, ...(opts.packageName ? { name: opts.packageName } : {}) },
    ...(opts.vendorAdvisory ? { vendorAdvisoryRef: opts.vendorAdvisory } : {}),
    patch: { status: opts.patchStatus, workersRestarted: !!opts.workersRestarted, mitigations: opts.mitigations ?? [] },
    verifiedAt: (opts.now ?? new Date()).toISOString(),
    provenance: {
      method: 'cli',
      tool: { name: 'php2shell-attest', version: '0.1.0' },
      ...(opts.collectedBy ? { collectedBy: opts.collectedBy } : {}),
      commands: opts.commands ?? [],
    },
  };
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) out[k] = true;
      else (out[k] = next), i++;
    } else out._.push(a);
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (cmd === 'keygen') {
    const key = generateKey();
    writeFileSync(args.out ?? 'attest-key.json', JSON.stringify(key, null, 2), { mode: 0o600 });
    console.log(`Key written to ${args.out ?? 'attest-key.json'} (keep it secret).`);
    console.log(`Trust this key in the extension by adding its fingerprint:\n${key.keyId}`);
    return;
  }
  if (cmd === 'report') {
    if (!args.origin) throw new Error('--origin is required');
    if (!args['patch-status']) throw new Error('--patch-status (fixed-upstream|vendor-backport-applied|not-patched|unknown) is required');
    const php = args['php-bin'] ?? 'php';
    const commands = [];
    let phpVersion = args['php-version'];
    let sapi;
    if (!phpVersion) {
      phpVersion = execFileSync(php, ['-r', 'echo PHP_VERSION;'], { encoding: 'utf8' }).trim();
      sapi = execFileSync(php, ['-r', 'echo PHP_SAPI;'], { encoding: 'utf8' }).trim();
      commands.push(`${php} -r 'echo PHP_VERSION;'`, `${php} -r 'echo PHP_SAPI;'`);
    }
    let report = buildReport({
      origin: args.origin,
      phpVersion,
      sapi,
      packageVersion: args['package-version'],
      osName: args['os-name'],
      osVersion: args['os-version'],
      packageSourceType: args['package-source'] ?? 'other',
      packageName: args['package-name'],
      vendorAdvisory: args['vendor-advisory'],
      patchStatus: args['patch-status'],
      workersRestarted: args['workers-restarted'] === true,
      mitigations: typeof args.mitigations === 'string' ? args.mitigations.split(',') : [],
      collectedBy: args['collected-by'],
      commands,
    });
    if (args.key) report = signReport(report, JSON.parse(readFileSync(args.key, 'utf8')));
    else console.error('Warning: no --key given; the report will be unsigned (self-reported).');
    const text = JSON.stringify(report, null, 2);
    if (args.out) writeFileSync(args.out, text);
    else console.log(text);
    return;
  }
  console.error('Usage: php2shell-attest keygen|report  (see header of this file)');
  process.exitCode = 2;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main();
