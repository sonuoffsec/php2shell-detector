import { useState } from 'react';
import type { Assessment } from '../assessment/engine';
import type { TrustedKey } from './browser';

const EXAMPLE = `{
  "schema": "php2shell-detector/owner-report",
  "schemaVersion": 1,
  "target": { "origin": "https://example.com" },
  "runtime": { "phpVersion": "8.3.36", "sapi": "fpm-fcgi" },
  "packageSource": { "type": "upstream-source" },
  "patch": { "status": "fixed-upstream", "workersRestarted": true, "mitigations": [] },
  "verifiedAt": "2026-10-23T09:00:00.000Z",
  "provenance": { "method": "cli", "tool": { "name": "php2shell-attest", "version": "0.1.0" } },
  "signature": { "alg": "Ed25519", "keyId": "…", "publicKey": "…", "value": "…" }
}`;

export interface OwnerPanelProps {
  assessment: Assessment | null;
  trustedKeys: TrustedKey[];
  onImport: (json: string) => void;
  onClear: () => void;
  onTrust: (keyId: string, label: string) => void;
  onUntrust: (keyId: string) => void;
  pendingUntrustedKey: string | null;
}

export function OwnerPanel(p: OwnerPanelProps) {
  const [text, setText] = useState('');
  const [fp, setFp] = useState('');
  const [label, setLabel] = useState('');
  const fpOk = /^[0-9a-f]{64}$/.test(fp.trim().toLowerCase());
  const a = p.assessment;

  return (
    <div className="panel" data-testid="owner-panel">
      <h2>Owner verification</h2>
      <p className="muted">
        A public-header scan cannot see the server’s PHP binary. If you administer the site, import a structured report to replace guesses with
        evidence. Imported data is validated locally and labelled <strong>self-reported</strong> unless it carries a valid signature from a key you
        trust.
      </p>

      <h3>1 · Generate a report (on the server)</h3>
      <pre className="code">{`node tools/php2shell-attest.mjs keygen --out attest-key.json
node tools/php2shell-attest.mjs report \\
  --origin ${a?.target.requestedOrigin ?? 'https://example.com'} \\
  --patch-status fixed-upstream --workers-restarted \\
  --package-source upstream-source \\
  --key attest-key.json --out report.json`}</pre>
      <p className="muted">
        The CLI reads the local <code>php</code> CLI binary, makes no network requests, and signs with Ed25519. Patch status and “workers restarted” are
        statements <em>you</em> make; the signature proves who signed, not that it is true.
      </p>

      <h3>2 · Import</h3>
      {!a && <p className="notice">Run an assessment first: a report is only valid for the origin it names.</p>}
      <label className="label" htmlFor="report-file">
        Report file (.json)
      </label>
      <input
        id="report-file"
        type="file"
        accept="application/json,.json"
        disabled={!a}
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (f && f.size < 100_000) p.onImport(await f.text());
        }}
      />
      <label className="label" htmlFor="report-text">
        …or paste JSON
      </label>
      <textarea id="report-text" rows={5} value={text} onChange={(e) => setText(e.target.value)} placeholder={EXAMPLE} disabled={!a} spellCheck={false} />
      <div className="row">
        <button className="btn" disabled={!a || !text.trim()} onClick={() => p.onImport(text)}>
          Validate & apply
        </button>
        <button
          className="btn ghost"
          disabled={!a}
          onClick={() => {
            setText('');
            p.onClear();
          }}
        >
          Remove report
        </button>
      </div>

      {a?.ownerErrors.length ? (
        <div className="notice error" role="alert" data-testid="owner-errors">
          <strong>Report rejected.</strong>
          <ul>
            {a.ownerErrors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {a?.owner && (
        <div className="card" data-testid="owner-summary">
          <p className="card-title">
            Imported report · <span className={`rel ${a.owner.provenance === 'attested' ? 'rel-high' : 'rel-low'}`}>{a.owner.provenance}</span>
          </p>
          <dl className="kv">
            <dt>PHP</dt>
            <dd>{a.owner.phpVersion}</dd>
            <dt>Patch status</dt>
            <dd>{a.owner.patchStatus}</dd>
            <dt>Verified at</dt>
            <dd>{a.owner.verifiedAt}</dd>
            <dt>Workers restarted</dt>
            <dd>{String(a.owner.workersRestarted)}</dd>
            <dt>Signature</dt>
            <dd>{a.owner.signature}</dd>
            <dt>Credited?</dt>
            <dd>{a.owner.credited ? 'Yes - changed the assessment state' : 'No - kept as an unverified claim'}</dd>
          </dl>
          {a.owner.blockers.length > 0 && (
            <ul className="blockers">
              {a.owner.blockers.map((b) => (
                <li key={b}>{b}</li>
              ))}
            </ul>
          )}
          {p.pendingUntrustedKey && (
            <div className="notice warn">
              <p>
                Signed by key <code className="wrap">{p.pendingUntrustedKey}</code> which you do not trust. Only trust it if you confirmed this
                fingerprint through a separate channel (for example, you generated it yourself).
              </p>
              <button className="btn" onClick={() => p.onTrust(p.pendingUntrustedKey!, 'Imported key')}>
                I verified this fingerprint - trust it
              </button>
            </div>
          )}
        </div>
      )}

      <h3>Trusted signing keys</h3>
      <p className="muted">Stored only in this browser. Trusting a key means you accept that its holder is who they say; it does not make their statements true.</p>
      {p.trustedKeys.length === 0 ? (
        <p className="muted">No trusted keys.</p>
      ) : (
        <ul className="plain" data-testid="trusted-keys">
          {p.trustedKeys.map((k) => (
            <li key={k.keyId} className="key-row">
              <span>
                <strong>{k.label}</strong>
                <br />
                <code className="wrap">{k.keyId}</code>
              </span>
              <button className="btn ghost" onClick={() => p.onUntrust(k.keyId)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="row stack">
        <label className="label" htmlFor="fp">
          Key fingerprint (SHA-256, 64 hex)
        </label>
        <input id="fp" value={fp} onChange={(e) => setFp(e.target.value)} spellCheck={false} />
        <label className="label" htmlFor="fp-label">
          Label
        </label>
        <input id="fp-label" value={label} onChange={(e) => setLabel(e.target.value)} />
        <button
          className="btn"
          disabled={!fpOk}
          onClick={() => {
            p.onTrust(fp.trim().toLowerCase(), label.trim() || 'Unnamed key');
            setFp('');
            setLabel('');
          }}
        >
          Add trusted key
        </button>
      </div>

      <h3>Report format</h3>
      <pre className="code small">{EXAMPLE}</pre>
    </div>
  );
}
