import type { OwnerReport, ReportSignature } from './schema';

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

export function b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function bytesToB64url(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function keyFingerprint(rawPublicKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', rawPublicKey as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const signingPayload = (report: OwnerReport): string => {
  const { signature: _omit, ...unsigned } = report;
  return canonicalize(unsigned);
};

export type SignatureCheck =
  | { status: 'none' }
  | { status: 'valid'; keyId: string }
  | { status: 'invalid'; reason: string }
  | { status: 'unverifiable'; reason: string };

// Checks the signature only. The result says nothing about whether the signer is trusted.
export async function verifySignature(report: OwnerReport): Promise<SignatureCheck> {
  const sig: ReportSignature | undefined = report.signature;
  if (!sig) return { status: 'none' };
  try {
    const raw = b64urlToBytes(sig.publicKey);
    if (raw.length !== 32) return { status: 'invalid', reason: 'Public key is not a 32-byte Ed25519 key.' };
    if ((await keyFingerprint(raw)) !== sig.keyId) {
      return { status: 'invalid', reason: 'keyId does not match the embedded public key.' };
    }
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey('raw', raw as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    } catch {
      return { status: 'unverifiable', reason: 'This browser does not support Ed25519 verification.' };
    }
    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      b64urlToBytes(sig.value) as BufferSource,
      new TextEncoder().encode(signingPayload(report)) as BufferSource,
    );
    return ok ? { status: 'valid', keyId: sig.keyId } : { status: 'invalid', reason: 'Signature does not match the report contents.' };
  } catch {
    return { status: 'invalid', reason: 'Signature is malformed.' };
  }
}
