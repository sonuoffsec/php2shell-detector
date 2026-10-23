import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { hostPatterns } from '../../src/popup/browser';

const manifest = JSON.parse(readFileSync('extension/static/manifest.json', 'utf8')) as Record<string, any>;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe('manifest and permissions (least privilege)', () => {
  it('is Manifest V3 with only activeTab + storage', () => {
    expect(manifest.manifest_version).toBe(3);
    expect([...manifest.permissions].sort()).toEqual(['activeTab', 'storage']);
  });

  it('has NO content scripts, background worker or remote code', () => {
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.background).toBeUndefined();
    expect(manifest.externally_connectable).toBeUndefined();
    expect(manifest.web_accessible_resources).toBeUndefined();
    const csp = manifest.content_security_policy.extension_pages as string;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/unsafe-eval|unsafe-inline|wasm-unsafe-eval/);
    const scriptSrc = /script-src ([^;]*)/.exec(csp)?.[1];
    expect(scriptSrc).toBe("'self'"); // no remote script origins
  });

  it('host access is limited to http(s) and declared at install (no per-site prompts); nothing optional', () => {
    expect(manifest.host_permissions).toEqual(['http://*/*', 'https://*/*']);
    expect(manifest.optional_host_permissions).toBeUndefined();
  });

  it('per-host patterns used at runtime are covered by host_permissions', () => {
    for (const origin of ['https://example.com', 'http://127.0.0.1:8080']) {
      for (const p of hostPatterns(origin)) expect(manifest.host_permissions).toContain(`${p.split('://')[0]}://*/*`);
    }
  });

  it('does not request permissions that would enable history/cookie/traffic collection', () => {
    const forbidden = ['tabs', 'history', 'cookies', 'webRequest', 'webRequestBlocking', 'declarativeNetRequest', 'scripting', 'downloads', 'management', 'nativeMessaging', 'debugger'];
    for (const p of forbidden) expect(manifest.permissions).not.toContain(p);
  });
});

describe('no backend, no telemetry (static source audit)', () => {
  const files = walk('src').filter((f) => /\.(ts|tsx)$/.test(f));
  const read = (f: string) => readFileSync(f, 'utf8');

  it('fetch is only used by the single scanner module', () => {
    const users = files.filter((f) => /\bfetch\s*\(|\bfetch\b\s*[:;,)]/.test(read(f).replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '')));
    expect(users.map((f) => f.replace(/\\/g, '/'))).toEqual(['src/scanner/collect.ts']);
  });

  it('uses no other network primitives', () => {
    for (const f of files) {
      expect(read(f), f).not.toMatch(/XMLHttpRequest|WebSocket|sendBeacon|EventSource|navigator\.connection|chrome\.runtime\.sendMessage|importScripts|eval\(|new Function/);
    }
  });

  it('contains no hard-coded third-party endpoints other than reference links and schema ids', () => {
    const allowedHosts = ['www.php.net', 'github.com', 'cloud.google.com', 'www.wiz.io', 'example.com', 'example.test', 'api.w.org', 'ubuntu.com'];
    for (const f of files.filter((x) => !x.endsWith('.json'))) {
      for (const m of read(f).matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
        const host = m[1]!.toLowerCase();
        expect(allowedHosts.some((h) => host === h || host.endsWith(`.${h}`)) || host === 'x.test', `${f}: ${host}`).toBe(true);
      }
    }
  });
});
