// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadBundledAdvisories } from '../../src/advisories';
import { assess, type Assessment } from '../../src/assessment/engine';
import { App } from '../../src/popup/App';
import { ResultView } from '../../src/popup/ResultView';
import { STATE_LABELS, type AssessmentState } from '../../src/shared/types';
import { evaluateOwnerReport } from '../../src/verification/evaluate';
import { buildReport, generateKey, signReport } from '../../tools/php2shell-attest.mjs';
import { NOW, ORIGIN, snapshot } from '../helpers/fixtures';

afterEach(() => cleanup());

const advisory = loadBundledAdvisories(NOW);
const key = generateKey();

async function make(state: AssessmentState): Promise<Assessment> {
  const mk = (headers: Record<string, string>, ownerJson?: object) =>
    ownerJson
      ? evaluateOwnerReport(JSON.stringify(ownerJson), { assessedOrigin: ORIGIN, advisory, trustedKeyIds: new Set([key.keyId]), now: NOW }).then((owner) =>
          assess({ requestedOrigin: ORIGIN, collect: snapshot(headers), advisory, owner, now: NOW }),
        )
      : Promise.resolve(assess({ requestedOrigin: ORIGIN, collect: snapshot(headers), advisory, now: NOW }));
  const rep = (over: object) =>
    buildReport({ origin: ORIGIN, phpVersion: '8.3.36', packageSourceType: 'upstream-source', patchStatus: 'fixed-upstream', workersRestarted: true, now: new Date('2026-10-24T00:00:00Z'), ...over });
  switch (state) {
    case 'potentially-exposed':
      return mk({ 'x-powered-by': 'PHP/8.3.1' });
    case 'exposure-indicators':
      return mk({ 'x-powered-by': 'PHP' });
    case 'mitigation-detected':
      return mk({ 'x-powered-by': 'PHP/8.3.1' }, rep({ phpVersion: '8.3.1', patchStatus: 'not-patched', mitigations: ['memory-limit-unlimited'] }));
    case 'patch-verified':
      return mk({}, signReport(rep({}), key));
    case 'inconclusive':
      return mk({ server: 'cloudflare', 'cf-ray': 'x' });
    case 'no-indicators':
      return mk({ server: 'nginx' });
  }
}

const ALL: AssessmentState[] = ['potentially-exposed', 'exposure-indicators', 'mitigation-detected', 'patch-verified', 'inconclusive', 'no-indicators'];

describe('every assessment state renders correctly', () => {
  it.each(ALL)('%s', async (state) => {
    const a = await make(state);
    expect(a.state).toBe(state);
    render(<ResultView a={a} />);
    expect(screen.getByTestId('state-badge')).toHaveTextContent(STATE_LABELS[state]);
    expect(screen.getByTestId('result')).toHaveTextContent(a.headline);
    expect(screen.getByTestId('section-evidence')).toBeInTheDocument();
    expect(screen.getByTestId('section-next')).toBeInTheDocument();
    expect(screen.getByTestId('section-unknown')).toBeInTheDocument();
    expect(screen.getAllByText(/CVE-2026-109618/).length).toBeGreaterThan(0);
    const badge = screen.getByTestId('state-badge').textContent ?? '';
    expect(badge).not.toMatch(/\b(secure|safe|vulnerable)\b/i);
    if (state === 'inconclusive' || state === 'no-indicators') {
      expect(screen.getByTestId('result').innerHTML).not.toMatch(/state-patch-verified/);
    }
  });

  it('shows evidence fields: source, time, type, reliability, what it does not prove', async () => {
    render(<ResultView a={await make('potentially-exposed')} />);
    const card = screen.getAllByTestId('evidence-card').find((c) => /PHP version/.test(c.textContent ?? ''))!;
    for (const t of ['Source', 'Collected', 'Type', 'Reliability', 'Does not prove', 'Direct observation', 'version observed']) {
      expect(card).toHaveTextContent(t);
    }
  });

  it('shows a stale-advisory warning and unavailable-advisory state', async () => {
    const stale = loadBundledAdvisories(new Date('2027-06-01T00:00:00Z'));
    const a = assess({ requestedOrigin: ORIGIN, collect: snapshot({ 'x-powered-by': 'PHP/8.3.1' }), advisory: stale, now: new Date('2027-06-01T00:00:00Z') });
    render(<ResultView a={a} />);
    expect(screen.getAllByText(/stale/i).length).toBeGreaterThan(0);
    cleanup();
    const none = assess({ requestedOrigin: ORIGIN, collect: snapshot({ 'x-powered-by': 'PHP/8.3.1' }), advisory: { available: false, reason: 'bad data' }, now: NOW });
    render(<ResultView a={none} />);
    expect(screen.getByText(/Advisory data is unavailable/)).toBeInTheDocument();
  });
});

describe('popup App end-to-end (jsdom, mocked network)', () => {
  it('assesses a typed URL with exactly one request and renders actual evidence', async () => {
    const fetchMock = vi.fn(async () =>
      (() => { const r = new Response('<html>BODY-SHOULD-NOT-APPEAR</html>', { status: 200, headers: { 'X-Powered-By': 'PHP/8.1.31', 'Set-Cookie': 'a=b' } }); Object.defineProperty(r, 'url', { value: 'https://shop.example.test/' }); return r; })(),
    );
    vi.stubGlobal('fetch', fetchMock);
    await act(async () => {
      render(<App />);
    });
    fireEvent.change(screen.getByLabelText('Website to assess'), { target: { value: 'https://shop.example.test/cart?x=1' } });
    expect(screen.getByTestId('origin-line')).toHaveTextContent('https://shop.example.test');
    fireEvent.click(screen.getByRole('button', { name: 'Assess website' }));
    await waitFor(() => expect(screen.getByTestId('result')).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect((fetchMock.mock.calls[0] as unknown[])[0]).toBe('https://shop.example.test/');
    expect(screen.getByTestId('state-badge')).toHaveTextContent('Potentially exposed');
    expect(document.body.textContent).not.toContain('BODY-SHOULD-NOT-APPEAR');
    expect(document.body.textContent).not.toMatch(/a=b/);
    vi.unstubAllGlobals();
  });

  it('refuses malformed input without making a request', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await act(async () => {
      render(<App />);
    });
    fireEvent.change(screen.getByLabelText('Website to assess'), { target: { value: 'ftp://nope' } });
    expect(screen.getByRole('button', { name: 'Assess website' })).toBeDisabled();
    expect(screen.getByTestId('origin-line')).toHaveTextContent(/Only http and https/);
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
