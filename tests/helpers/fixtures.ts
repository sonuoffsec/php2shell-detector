import type { CollectResult } from '../../src/scanner/collect';

export const NOW = new Date('2026-10-25T12:00:00.000Z');

export function snapshot(headers: Record<string, string>, opts: { status?: number; finalOrigin?: string; redirected?: boolean } = {}): CollectResult {
  return {
    ok: true,
    redirected: opts.redirected ?? false,
    snapshot: {
      status: opts.status ?? 200,
      finalUrlOrigin: opts.finalOrigin ?? 'https://example.test',
      headers,
      collectedAt: NOW.toISOString(),
    },
  };
}

export const ORIGIN = 'https://example.test';
