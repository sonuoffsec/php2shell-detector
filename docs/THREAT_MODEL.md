# Security architecture and threat model

## Architecture

```
 Chrome popup (React, extension page)                      no service worker, no content script
 ┌──────────────────────────────────────────────────────────────────────────────────────┐
 │ App.tsx ─ user clicks "Assess" ─▶ browser.ts: host access (manifest-declared)
 │                                  │                                                   │
 │                                  ▼                                                   │
 │  scanner/collect.ts  ── single GET <origin>/ ─────────────▶ target site (only host)  │
 │        │  headers → allowlist + scrub (privacy/redact.ts)                            │
 │        ▼                                                                             │
 │  scanner/fingerprints.ts ─▶ assessment/engine.ts ◀─ advisories/ (bundled JSON, zod)  │
 │                                  ▲                                                   │
 │  verification/ (zod + Ed25519) ──┘  imported owner report (user-supplied file)       │
 │        ▼                                                                             │
 │  reports/ (JSON, Markdown; redacted) ─▶ Blob download in the popup                   │
 │  storage: chrome.storage.local - settings, trusted key fingerprints, optional history│
 └──────────────────────────────────────────────────────────────────────────────────────┘
```

Everything runs in the popup. There is no server, account, telemetry, remote configuration or remote code.

## Assets

1. The user's browsing privacy (URLs, history, cookies, sessions).
2. The integrity of the verdict (a wrong "patched/safe" reading is the worst failure).
3. The trust list of signing keys.
4. Third-party systems (we must not harm or probe them).

## Trust boundaries and threats

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Hostile target returns crafted headers/values (XSS, huge values, ReDoS) | Values rendered by React as text; allowlisted headers only; values truncated at 200 chars; simple anchored regexes; body never read | A hostile site can still lie about its version |
| T2 | Hostile site spoofs a patched version to appear safe | "Fixed version" yields *No indicators*, never *Patch verified*; conflicts → Inconclusive | Consistent forgery is undetectable passively; documented |
| T3 | Hostile site hides a vulnerable version | Absence ≠ safe; wording and `unknowns` say so | Inherent to passive assessment |
| T4 | Redirect to an attacker or third-party host so the extension "scans" it | The extension cannot read the response of a redirect target the user did not grant (the fetch fails and is reported as a failure); if it is readable, the verdict is Inconclusive (R02) and the host is named; never auto-assessed | `fetch` follows redirects automatically, so the **browser may still send the request** to the redirect destination even when its response is withheld from the extension. This is inherent to the platform |
| T5 | User tricked into assessing an internal / localhost address (SSRF-like) | The request originates from the user's own browser, only when the user clicks Assess; the origin is displayed before the click; no result is sent anywhere | The popup is a local network client by nature; users should assess only authorised targets |
| T6 | Malicious owner report (forged patch claim) | Schema validation, origin binding, age/skew checks; unsigned or untrusted-signed reports are never credited for *Patch verified* | A trusted signer can lie; stated in UI and docs |
| T7 | Tampered report with a valid-looking signature | Ed25519 over canonical JSON; keyId must equal SHA-256(pubkey); invalid ⇒ reject, no downgrade | Key compromise |
| T8 | Social engineering into trusting an attacker's key | Trust requires an explicit click with a fingerprint warning; keys can be removed | User error |
| T9 | Sensitive data leaks into exports | Allowlist at collection + `redactDeep` on export; tests assert cookies/tokens/bodies/paths are absent | Free-text values could contain secrets we do not recognise; they are limited to allowlisted headers |
| T10 | Supply-chain compromise (npm) | Exact version pins, lockfile, no runtime deps beyond React/Radix/zod; `npm ci`; no remote script, CSP `script-src 'self'` | Dependencies still need periodic review |
| T11 | Malicious update / remote code | No `eval`, no remote scripts, no `importScripts`, no remotely fetched rules; audit script fails the build otherwise | – |
| T12 | The tool is used offensively | Single benign `GET /`; no payloads, no OOM/UAF triggers, no crawling, no background scanning; user-initiated only | A GET is not exploitation, but the README restricts use to authorised targets |
| T13 | Stale advisory data causes a wrong conclusion | `lastVerifiedAt` / `maxAgeDays`; stale ⇒ banner and "fixed" readings become Inconclusive | Data only changes with a new release (by design: no backend) |
| T14 | `chrome.storage` tampering by other extensions | Not possible across extensions; local malware is out of scope | – |

## Explicitly out of scope / not implemented

Exploit payloads, RCE attempts, webshells, credential extraction, DoS/OOM triggering, crawling, scanning browsing history, stealth/evasion, an "active testing mode". If one is ever considered it needs a separate authorisation model, safety controls and independent review first (see ROADMAP).

## Permission justification

See `docs/PRIVACY.md`.

## Failure behaviour

Network error, timeout, storage unavailable, invalid advisory data, invalid report, unsupported Ed25519 → each produces an explicit *Inconclusive*/rejected/"unverifiable" outcome with a reason. None silently falls back to a more favourable verdict.
