import * as Collapsible from '@radix-ui/react-collapsible';
import { useState, type ReactNode } from 'react';
import type { Assessment } from '../assessment/engine';
import { buildJsonReport } from '../reports/json';
import { buildTextReport } from '../reports/text';
import { STATE_LABELS, type AssessmentState, type Evidence } from '../shared/types';

export const STATE_GLYPH: Record<AssessmentState, string> = {
  'potentially-exposed': '⚠',
  'exposure-indicators': '◆',
  'mitigation-detected': '◐',
  'patch-verified': '✔',
  inconclusive: '?',
  'no-indicators': '○',
};

export function StateBadge({ state }: { state: AssessmentState }) {
  return (
    <span className={`badge state-${state}`} data-testid="state-badge">
      <span aria-hidden="true" className="glyph">
        {STATE_GLYPH[state]}
      </span>
      {STATE_LABELS[state]}
    </span>
  );
}

function Section({ title, children, defaultOpen = true, id }: { title: string; children: ReactNode; defaultOpen?: boolean; id: string }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Collapsible.Root open={open} onOpenChange={setOpen} className="section" data-testid={`section-${id}`}>
      <Collapsible.Trigger className="section-trigger">
        <span aria-hidden="true" className="chev">
          {open ? '▾' : '▸'}
        </span>
        {title}
      </Collapsible.Trigger>
      <Collapsible.Content className="section-body">{children}</Collapsible.Content>
    </Collapsible.Root>
  );
}

const directLabel: Record<Evidence['directness'], string> = {
  direct: 'Direct observation',
  inference: 'Inference',
  'self-reported': 'Self-reported',
  attested: 'Attested (signed)',
};

function EvidenceCard({ e }: { e: Evidence }) {
  return (
    <li className="card" data-testid="evidence-card">
      <p className="card-title">{e.summary}</p>
      <dl className="kv">
        <dt>Observed</dt>
        <dd>
          <code>{e.value}</code>
        </dd>
        <dt>Source</dt>
        <dd>
          {e.source.type} · {e.source.name} · {e.source.origin}
        </dd>
        <dt>Collected</dt>
        <dd>{new Date(e.collectedAt).toLocaleString()}</dd>
        <dt>Type</dt>
        <dd>
          {directLabel[e.directness]}
          {e.versionProvenance ? ` · version ${e.versionProvenance}` : ''}
        </dd>
        <dt>Reliability</dt>
        <dd>
          <strong className={`rel rel-${e.reliability}`}>{e.reliability}</strong> - {e.reliabilityReason}
        </dd>
        <dt>Does not prove</dt>
        <dd>
          <ul className="plain">
            {e.doesNotProve.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
        </dd>
      </dl>
    </li>
  );
}

function download(name: string, mime: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function ResultView({ a, extra }: { a: Assessment; extra?: ReactNode }) {
  const [copied, setCopied] = useState(false);
  const host = a.target.requestedHost.replace(/[^a-z0-9.-]/gi, '_');
  const stamp = a.assessedAt.slice(0, 10);
  return (
    <div data-testid="result" aria-live="polite">
      <div className={`verdict state-${a.state}`}>
        <StateBadge state={a.state} />
        <h2 className="headline">{a.headline}</h2>
        <ul className="plain rationale">
          {a.rationale.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
        <p className="meta">
          Confidence: <strong>{a.confidence.level}</strong> (qualitative label, not a probability) · rule <code>{a.ruleId}</code>
        </p>
      </div>

      {a.target.redirected && (
        <p className="notice" role="note">
          Redirect: <code>{a.target.requestedOrigin}</code> → <code>{a.target.finalOrigin ?? 'unknown'}</code>
          {a.target.hostChanged ? ' - a different host. It was not assessed as the requested site.' : ' - same host.'}
        </p>
      )}
      {a.warnings.map((w) => (
        <p className="notice warn" role="note" key={w}>
          {w}
        </p>
      ))}
      {extra}

      <Section id="evidence" title={`Evidence collected (${a.evidence.length})`}>
        {a.evidence.length === 0 ? (
          <p className="muted">No evidence was collected.</p>
        ) : (
          <ul className="plain cards">
            {a.evidence.map((e) => (
              <EvidenceCard e={e} key={e.id} />
            ))}
          </ul>
        )}
      </Section>

      <Section id="cves" title="Related CVEs and advisory sources">
        {a.cves.length === 0 ? (
          <p className="muted">Advisory data is unavailable: {a.advisory.note}</p>
        ) : (
          <>
            <ul className="plain">
              {a.cves.map((c) => (
                <li key={c.id}>
                  <strong>{c.id}</strong> {c.ghsa ? <span className="muted">({c.ghsa})</span> : null}
                  <br />
                  <span className="muted">{c.summary}</span>
                </li>
              ))}
            </ul>
            <p>
              <strong>Fixed upstream:</strong> {a.fixedReleases.map((f) => f.fixedIn).join(', ')}. Packaged builds may carry a vendor backport under an older version number.
            </p>
            <p className={a.advisory.stale ? 'notice warn' : 'muted'}>
              Dataset <code>{a.advisory.datasetId}</code> verified {a.advisory.verifiedAt}
              {a.advisory.stale ? ' - STALE, re-verify.' : '.'}
            </p>
            <ul className="plain refs">
              {a.references.map((r) => (
                <li key={r.id}>
                  <a href={r.url} target="_blank" rel="noopener noreferrer">
                    {r.title}
                  </a>{' '}
                  <span className="muted">
                    · {r.publisher} · checked {r.checkedAt}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Section>

      <Section id="unknown" title="What remains unknown">
        <ul>
          {a.unknowns.map((u) => (
            <li key={u}>{u}</li>
          ))}
        </ul>
      </Section>

      <Section id="next" title="Remediation and verification">
        <ol className="steps">
          {a.nextSteps.map((s) => (
            <li key={s.id}>
              <strong>{s.title}</strong>
              <br />
              <span className="muted">{s.detail}</span>
            </li>
          ))}
        </ol>
      </Section>

      <Section id="export" title="Export report" defaultOpen={false}>
        <p className="muted">Redacted: no cookies, credentials, authorization headers, full header sets, URL paths or response bodies.</p>
        <div className="row">
          <button className="btn" onClick={() => download(`php2shell-${host}-${stamp}.json`, 'application/json', JSON.stringify(buildJsonReport(a), null, 2))}>
            Download JSON
          </button>
          <button className="btn" onClick={() => download(`php2shell-${host}-${stamp}.md`, 'text/markdown', buildTextReport(a))}>
            Download report (Markdown)
          </button>
          <button
            className="btn ghost"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(buildTextReport(a));
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              } catch {
                /* clipboard blocked */
              }
            }}
          >
            {copied ? 'Copied' : 'Copy report'}
          </button>
        </div>
      </Section>
    </div>
  );
}
