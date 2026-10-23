# Privacy, permissions and data disclosure

## Permissions (`extension/static/manifest.json`)

| Permission | Why | Not used for |
|---|---|---|
| `activeTab` | When you open the popup, read the **URL of the current tab** to prefill the target box | Reading page content, other tabs, or history |
| `storage` | Remember settings, the list of signing-key fingerprints you chose to trust, and (only if enabled) a small local history | Syncing anywhere; it is `storage.local` |
| `host_permissions` (`http://*/*`, `https://*/*`) | Granted at install (Chrome warns: "read and change your data on all websites"). Needed so the popup can read the response headers of **whichever site you type**, without a permission prompt per site. A browser cannot read cross-origin response headers without it | Anything automatic: the code contacts a site **only** when you click Assess, a test asserts `fetch` is used in exactly one module, there are no content scripts, no background worker, and no page content is read |

> **Trade-off, stated plainly.** This is broader than the earlier per-site design (which asked Chrome for one host at a time). The wide grant is a convenience choice; the *behaviour* is still one `GET /` per click. A user who prefers least privilege can set **Site access → On click / specific sites** in `chrome://extensions`, and the popup will then ask Chrome for the single host it needs. The Chrome Web Store may require extra justification for broad host access (see `docs/RELEASE.md`).

Not requested: `tabs`, `history`, `cookies`, `webRequest`, `scripting`, `downloads`, `declarativeNetRequest`, content scripts, a background worker. A test (`tests/unit/manifest.test.ts`) and the build audit (`scripts/check-dist.mjs`) enforce this and pin the host patterns to exactly `http://*/*` and `https://*/*`.

> Redirects: `fetch` follows redirects automatically. With site access on, a redirect to a **different** host is readable, so it is reported and the verdict is Inconclusive (rule R02) - it is never assessed as the requested site.

## Network requests (all of them)

1. After you press **Assess website**: one `GET <origin>/` to that site. No cookies/credentials (`credentials: 'omit'`), no custom headers, no referrer, path/query not sent, body not read, 10 s timeout.
2. Advisory reference links are plain `<a>` links opened **only when you click them**.

That is the complete list. There is no analytics, no error reporting, no update-check, no backend.

## Data handled

| Data | Where | Retention |
|---|---|---|
| Target origin | popup memory | until the popup closes |
| Allowlisted response headers (`server`, `x-powered-by`, `via`, `x-generator`, `link`, CDN ids…) with query strings/tokens scrubbed | popup memory | until the popup closes |
| Imported owner report text | popup memory | until the popup closes |
| Trusted key fingerprints + labels | `chrome.storage.local` | until you remove them / delete data |
| Settings | `chrome.storage.local` | same |
| History (**off by default**): origin, state label, time | `chrome.storage.local` | last 20, until cleared |

Never stored or exported: cookies, `Set-Cookie`, authorization headers, API keys, full header sets, URL paths/queries, response bodies. "Delete all locally stored data" in *Privacy & method* clears everything.

Exported reports are created in the popup and saved by your browser; they are never uploaded by the extension. They contain the target origin, so handle them accordingly.

## Privacy policy

The store-facing policy is [`docs/privacy-policy.html`](privacy-policy.html), published with GitHub Pages at:

https://sonuoffsec.github.io/php2shell-detector/privacy-policy.html

Keep it in sync with this document. Contact is the repository's issue tracker, so no personal email is published.

## Chrome Web Store "Privacy practices" tab - suggested answers

* **Single purpose:** Assess a user-chosen website for PHP2Shell exposure indicators and guide verification.
* **Permission justifications:** copy the table above.
* **Data collection:** declare *Website content*: **No**. *Web history*: **No**. *Authentication information*: **No**. *Personally identifiable information*: **No**. The only user-provided inputs (target URL, owner report) are processed locally and not transmitted to the developer. If your reviewer considers the target URL "user activity", declare that it is processed locally only.
* **Remote code:** No.
* Certify the three limited-use statements (no sale, no unrelated use, no creditworthiness use).
