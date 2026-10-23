# Chrome Web Store publishing checklist

## 1. Before every release

- [ ] Re-verify the advisory dataset against php.net, both GHSAs and Google Cloud; update `src/advisories/data/php2shell.json` (`lastVerifiedAt`, per-reference `checkedAt`, `updated`) - especially the ≤ 8.1 backport discrepancy and any vendor advisories.
- [ ] Bump `version` in `package.json` **and** `extension/static/manifest.json` (and `TOOL_VERSION` in `src/reports/json.ts`).
- [ ] `npm ci && npm run typecheck && npm test && npm run build` - all green. The build runs `scripts/check-dist.mjs` (release manifest unchanged, permissions = `activeTab`+`storage` + http(s) host access, no `key`, no remote scripts, no unexpected hosts).
- [ ] `npm run test:e2e` green; `npm run screenshots` if the UI changed.
- [ ] `npm audit --omit=dev` reviewed; dependency versions still pinned exactly.

## 2. Manual checks (not automatable)

Load `dist/` unpacked in a normal Chrome profile and confirm:

- [ ] Popup on an `https://` page prefills the origin (activeTab).
- [ ] Install shows Chrome's "read and change your data on all websites" warning once; **Assess** then runs with no further prompt.
- [ ] Exactly one `GET /` to the chosen host (popup DevTools → Network): no `Cookie`, `Authorization`, `Referer`; nothing is sent when the popup merely opens.
- [ ] If Site access is set to "On click"/"specific sites" in chrome://extensions, Assess shows the guidance message or Chrome's prompt.
- [ ] `http://` site that redirects to `https://` same host works; a redirect to another host is reported as failure/Inconclusive, not assessed.
- [ ] Exports download; open them and grep for cookies/tokens (none).
- [ ] Settings → "Delete all locally stored data" clears trusted keys/history.
- [ ] Chrome ≥ 137 verifies a CLI-signed report; an older Chrome shows "unverifiable".
- [ ] Test against a **real** PHP stack you own (mod_php, FPM, a distro package) and record the observed headers vs. verdict.

## 3. Package

```bash
npm run package     # typecheck, build, bundle audit, then writes php2shell-detector-<version>.zip
```

The script zips `dist/` with forward-slash paths and `manifest.json` at the zip root.

(`dist/manifest.json` must be at the zip root.) Never upload `dist-e2e/`.

## 4. Listing

* **Name:** PHP2Shell Detector - **Category:** Developer Tools.
* **Single purpose:** Assess a user-chosen website for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure indicators and guide verification.
* **Short description (≤ 132 chars):** Passive, evidence-first check for PHP2Shell exposure. Shows what was observed, what it can't prove, and how to verify.
* **Detailed description** - lead with: passive and user-initiated; one request per assessment to the site you choose; no backend/analytics; six states, not Vulnerable/Safe; owner verification with signed reports; limits (hidden headers, backports, CDNs). Don't claim it detects "all vulnerable sites" or that "no indicators" means safe.
* **Screenshots (1280×800):** upload the files in `store/screenshots/` (made by `npm run screenshots` from the real UI).
* **Branding risk:** the logo in `logo/PHP2.png` contains the PHP elephant. The store can reject listings that look like they come from the PHP project, and the PHP Group has its own rules for that mark. Check the licence terms for the elephant artwork, or ship a logo without it. Also do not use Eye Security's branding, and do not imply affiliation with Wiz, Google or the PHP Group.

## 5. Privacy tab

Copy answers from `docs/PRIVACY.md` (permission justifications, "no data collected", no remote code). Privacy policy URL for the listing: https://sonuoffsec.github.io/php2shell-detector/privacy-policy.html (GitHub Pages, branch `main`, folder `/docs`). The policy and the Privacy tab answers must match.

## 6. Policy self-review

- [ ] Single purpose yes · no remotely hosted code yes (CSP `script-src 'self'`, audit script) · permissions minimal in *behaviour* yes but **broad host access (`http(s)://*/*`) needs justification** - expect extra review; consider reverting to optional per-site host permissions for the store build.
- [ ] Reviewer note: *"Host access is used only after the user clicks 'Assess website', to read the response headers of the one site the user typed, because a browser cannot read cross-origin response headers without it. No content scripts, no background worker, no data leaves the browser."*
- [ ] Developer contact and support URL set.
