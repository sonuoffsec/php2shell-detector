import * as Tabs from '@radix-ui/react-tabs';
import { useCallback, useEffect, useRef, useState } from 'react';
import { loadBundledAdvisories } from '../advisories';
import { assess, type Assessment } from '../assessment/engine';
import { collectSnapshot, type CollectResult } from '../scanner/collect';
import { parseTarget } from '../scanner/target';
import { evaluateOwnerReport, type OwnerOutcome } from '../verification/evaluate';
import { AboutPanel } from './AboutPanel';
import {
  clearAll,
  ensureHostAccess,
  getActiveTabUrl,
  loadHistory,
  loadSettings,
  loadTrustedKeys,
  saveHistory,
  saveSettings,
  saveTrustedKeys,
  DEFAULT_SETTINGS,
  type HistoryEntry,
  type Settings,
  type TrustedKey,
} from './browser';
import { OwnerPanel } from './OwnerPanel';
import { ResultView } from './ResultView';
import { STATE_LABELS } from '../shared/types';

type Status = 'idle' | 'permission' | 'working' | 'done' | 'error';

interface Snapshot {
  origin: string;
  collect: CollectResult;
  ownerJson: string | null;
}

export function App() {
  const [input, setInput] = useState('');
  const [status, setStatus] = useState<Status>('idle');
  const [error, setError] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [ownerOutcome, setOwnerOutcome] = useState<OwnerOutcome | null>(null);
  const [tab, setTab] = useState('assess');
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [trusted, setTrusted] = useState<TrustedKey[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const snap = useRef<Snapshot | null>(null);

  useEffect(() => {
    void (async () => {
      setSettings(await loadSettings());
      setTrusted(await loadTrustedKeys());
      setHistory(await loadHistory());
      const url = await getActiveTabUrl();
      if (url) setInput(url);
    })();
  }, []);

  const parsed = parseTarget(input);

  const compute = useCallback(
    async (s: Snapshot, keys: TrustedKey[]): Promise<Assessment> => {
      const advisory = loadBundledAdvisories();
      const owner = s.ownerJson
        ? await evaluateOwnerReport(s.ownerJson, {
            assessedOrigin: s.origin,
            advisory,
            trustedKeyIds: new Set(keys.map((k) => k.keyId)),
            now: new Date(),
          })
        : null;
      setOwnerOutcome(owner);
      const result = assess({ requestedOrigin: s.origin, collect: s.collect, advisory, owner });
      setAssessment(result);
      return result;
    },
    [],
  );

  const run = async (): Promise<void> => {
    const t = parseTarget(input);
    if (!t.ok) {
      setError(t.error);
      setStatus('error');
      return;
    }
    setError(null);
    setAssessment(null);
    setOwnerOutcome(null);
    setStatus('permission');
    const access = await ensureHostAccess(t.origin);
    if (access === 'denied') {
      setError(`Chrome is blocking this extension from accessing ${t.host}. In chrome://extensions → PHP2Shell Detector → Details, set Site access to “On all sites”.`);
      setStatus('error');
      return;
    }
    setStatus('working');
    const collect = await collectSnapshot(t.origin);
    snap.current = { origin: t.origin, collect, ownerJson: null };
    const result = await compute(snap.current, trusted);
    setStatus('done');
    if (settings.historyEnabled) {
      const next = [{ origin: t.origin, state: STATE_LABELS[result.state], at: result.assessedAt }, ...history].slice(0, 20);
      setHistory(next);
      await saveHistory(next);
    }
  };

  const importReport = async (json: string): Promise<void> => {
    if (!snap.current) return;
    snap.current = { ...snap.current, ownerJson: json };
    await compute(snap.current, trusted);
  };

  const updateTrust = async (keys: TrustedKey[]): Promise<void> => {
    setTrusted(keys);
    await saveTrustedKeys(keys);
    if (snap.current) await compute(snap.current, keys);
  };

  const pendingUntrusted =
    ownerOutcome?.accepted && ownerOutcome.signature.state === 'valid-untrusted' ? (ownerOutcome.signature.keyId ?? null) : null;

  const busy = status === 'permission' || status === 'working';

  return (
    <main className="app">
      <header className="brand">
        <img className="logo" src="icons/icon48.png" width="36" height="36" alt="" />
        <div>
          <h1>PHP2Shell Detector</h1>
          <p className="tagline">Detect exposure. Verify the evidence.</p>
        </div>
      </header>

      <section className="target" aria-label="Target">
        <label htmlFor="target" className="label">
          Website to assess
        </label>
        <div className="row">
          <input
            id="target"
            type="text"
            inputMode="url"
            placeholder="https://example.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !busy && void run()}
            spellCheck={false}
            aria-invalid={input.trim() !== '' && !parsed.ok}
            aria-describedby="origin-line"
          />
          <button className="btn primary" onClick={() => void run()} disabled={busy || !parsed.ok}>
            {busy ? 'Assessing…' : 'Assess website'}
          </button>
        </div>
        <p id="origin-line" className="muted origin" data-testid="origin-line">
          {parsed.ok ? (
            <>
              Origin assessed: <code>{parsed.origin}</code> (path and query are not sent)
            </>
          ) : input.trim() ? (
            parsed.error
          ) : (
            'Enter a URL or open the popup on a page. Only the origin’s “/” is requested, once.'
          )}
        </p>
      </section>

      <Tabs.Root value={tab} onValueChange={setTab}>
        <Tabs.List className="tabs" aria-label="Sections">
          <Tabs.Trigger value="assess" className="tab">
            Assessment
          </Tabs.Trigger>
          <Tabs.Trigger value="owner" className="tab">
            Owner verification
          </Tabs.Trigger>
          <Tabs.Trigger value="about" className="tab">
            Privacy &amp; method
          </Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="assess" className="tabpanel">
          {status === 'idle' && !assessment && (
            <p className="muted empty">No assessment yet. Results show the evidence behind them - and what that evidence cannot prove.</p>
          )}
          {status === 'permission' && <p className="status" role="status">Waiting for Chrome’s site-access prompt…</p>}
          {status === 'working' && <p className="status" role="status">Requesting {parsed.ok ? parsed.origin : 'the site'} once and reading response headers…</p>}
          {status === 'error' && error && (
            <p className="notice error" role="alert" data-testid="error">
              {error}
            </p>
          )}
          {assessment && <ResultView a={assessment} />}
        </Tabs.Content>

        <Tabs.Content value="owner" className="tabpanel">
          <OwnerPanel
            assessment={assessment}
            trustedKeys={trusted}
            pendingUntrustedKey={pendingUntrusted}
            onImport={(j) => void importReport(j)}
            onClear={() => {
              if (snap.current) {
                snap.current = { ...snap.current, ownerJson: null };
                void compute(snap.current, trusted);
              }
            }}
            onTrust={(keyId, label) => void updateTrust([...trusted.filter((k) => k.keyId !== keyId), { keyId, label, addedAt: new Date().toISOString() }])}
            onUntrust={(keyId) => void updateTrust(trusted.filter((k) => k.keyId !== keyId))}
          />
        </Tabs.Content>

        <Tabs.Content value="about" className="tabpanel">
          <AboutPanel
            settings={settings}
            history={history}
            onSettings={(s) => {
              setSettings(s);
              void saveSettings(s);
            }}
            onClearData={() => {
              void clearAll();
              setSettings(DEFAULT_SETTINGS);
              setTrusted([]);
              setHistory([]);
            }}
          />
        </Tabs.Content>
      </Tabs.Root>
    </main>
  );
}
