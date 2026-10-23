import { minimizeHeaders } from '../privacy/redact';
import type { ResponseSnapshot } from '../shared/types';

export type CollectResult =
  | { ok: true; snapshot: ResponseSnapshot; redirected: boolean }
  | { ok: false; error: string; kind: 'timeout' | 'network' | 'aborted' };

export interface CollectOptions {
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

// The only request the extension makes: one GET of <origin>/ with no credentials, cookies, custom
// headers or referrer. The browser follows redirects (the final origin is reported). The body is never read.
export async function collectSnapshot(origin: string, opts: CollectOptions = {}): Promise<CollectResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await doFetch(`${origin}/`, {
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'follow',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    void res.body?.cancel().catch(() => undefined);
    let finalOrigin = origin;
    try {
      if (res.url) finalOrigin = new URL(res.url).origin;
    } catch {
      /* keep requested origin */
    }
    return {
      ok: true,
      redirected: res.redirected || finalOrigin !== origin,
      snapshot: {
        status: res.status,
        finalUrlOrigin: finalOrigin,
        headers: minimizeHeaders(res.headers.entries()),
        collectedAt: (opts.now?.() ?? new Date()).toISOString(),
      },
    };
  } catch (e) {
    if (controller.signal.aborted) return { ok: false, kind: 'timeout', error: 'The request timed out.' };
    return {
      ok: false,
      kind: 'network',
      error:
        'The site could not be reached (DNS, TLS or connection failure) - or it redirected to a host this extension has no access to, whose response the extension is not allowed to read.',
    };
  } finally {
    clearTimeout(timer);
  }
}
