import type { TargetInfo } from '../shared/types';

export type TargetParse = { ok: true; origin: string; host: string } | { ok: false; error: string };

// Reduces input to an exact origin. Only http(s), no embedded credentials, bare hosts default to https,
// and the path, query and fragment are dropped.
export function parseTarget(input: string): TargetParse {
  const trimmed = input.trim();
  if (!trimmed) return { ok: false, error: 'Enter a URL to assess.' };
  if (/\s/.test(trimmed)) return { ok: false, error: 'URLs cannot contain spaces.' };
  const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(trimmed) && !/^[^/]+:\d+(\/|$)/.test(trimmed);
  const candidate = hasScheme || trimmed.startsWith('//') ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(candidate.startsWith('//') ? `https:${candidate}` : candidate);
  } catch {
    return { ok: false, error: 'That does not look like a valid URL.' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: `Only http and https targets are supported (got ${url.protocol}).` };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'URLs with embedded credentials are not accepted.' };
  }
  if (!url.hostname) return { ok: false, error: 'The URL has no host.' };
  return { ok: true, origin: url.origin, host: url.hostname };
}

export function buildTargetInfo(requestedOrigin: string, finalOrigin: string | null, redirected: boolean): TargetInfo {
  const requestedHost = new URL(requestedOrigin).hostname;
  const finalHost = finalOrigin ? new URL(finalOrigin).hostname : null;
  return {
    requestedOrigin,
    requestedHost,
    finalOrigin,
    finalHost,
    redirected,
    originChanged: finalOrigin !== null && finalOrigin !== requestedOrigin,
    hostChanged: finalHost !== null && finalHost !== requestedHost,
  };
}

export const hostPermissionPattern = (origin: string): string => `${origin}/*`;
