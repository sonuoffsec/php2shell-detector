import type { HistoryEntry, Settings } from './browser';

export interface AboutPanelProps {
  settings: Settings;
  history: HistoryEntry[];
  onSettings: (s: Settings) => void;
  onClearData: () => void;
}

export function AboutPanel({ settings, history, onSettings, onClearData }: AboutPanelProps) {
  return (
    <div className="panel" data-testid="about-panel">
      <h2>Privacy</h2>
      <ul>
        <li>
          <strong>One request per assessment:</strong> a single <code>GET {'<origin>'}/</code> to the site you chose - no cookies, no credentials,
          no custom headers, no referrer. The body is never read.
        </li>
        <li>No backend, account, telemetry or analytics. Assessment and report generation happen in this popup, on your device.</li>
        <li>Only a small allowlist of fingerprint headers is kept; cookies and authorization values are never stored or exported.</li>
        <li>Your browsing history is never read. The extension sees the active tab’s URL only when you open the popup (activeTab).</li>
        <li>
          The extension declares access to http(s) sites so it can read response headers of whichever site you choose without a per-site prompt. It only contacts a site when you click “Assess website”, and never in the background.
        </li>
      </ul>

      <h2>Settings</h2>
      <label className="check">
        <input type="checkbox" checked={settings.historyEnabled} onChange={(e) => onSettings({ ...settings, historyEnabled: e.target.checked })} />
        Save a local history (origin, result, time - nothing else)
      </label>
      {settings.historyEnabled && (
        <ul className="plain history" data-testid="history">
          {history.length === 0 && <li className="muted">No assessments saved yet.</li>}
          {history.map((h) => (
            <li key={`${h.origin}${h.at}`}>
              {h.origin} · {h.state} · {new Date(h.at).toLocaleString()}
            </li>
          ))}
        </ul>
      )}
      <button className="btn ghost" onClick={onClearData}>
        Delete all locally stored data
      </button>

      <h2>Methodology (short)</h2>
      <ol>
        <li>Normalise the URL to an exact origin; follow redirects but report them.</li>
        <li>Read response headers only; keep an allowlist; redact the rest.</li>
        <li>Compare a disclosed PHP version to the bundled, source-referenced advisory data.</li>
        <li>Apply transparent rules (each result shows its rule ID). A missing version is never guessed.</li>
        <li>Optionally upgrade the finding with a validated owner report.</li>
      </ol>
      <h3>Limits</h3>
      <ul>
        <li>Headers can be hidden, stale, spoofed, or differ per node; CDNs hide the origin.</li>
        <li>Vendor backports keep old version numbers - a version alone is never proof of vulnerability.</li>
        <li>“No indicators detected” is not “safe”. “Patch verified” requires a trusted signed owner attestation.</li>
        <li>Advisory data covers only CVE-2026-109618 and CVE-2026-109619 and must be kept current.</li>
        <li>Nothing here sends exploit payloads or tries to execute code.</li>
      </ul>
      <p className="muted">Use only on systems you own or are authorised to assess. v0.1.0 · defensive assessment tool, provided without warranty.</p>
    </div>
  );
}
