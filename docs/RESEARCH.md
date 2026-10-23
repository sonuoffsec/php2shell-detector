# Phase 1 - Research and gap analysis

Date checked: **2026-10-23** (two days after disclosure). Facts below were read from the cited pages on that date by fetching them; the bundled dataset in `src/advisories/data/php2shell.json` records the same per-source claims and `checkedAt` dates.

## 1. Advisory verification

| Fact | Source(s) | Status |
|---|---|---|
| CVE-2026-109618 (GHSA-w8hw-w9fx-j79w): OOM handling interrupts PHP while request data is partially initialised; cleanup treats it as valid | php.net archive, Google Cloud, GHSA page | Confirmed by 3 sources |
| CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp): request-owned state survives after free; reused by a later request on the same worker | php.net archive, Google Cloud, GHSA page | Confirmed by 3 sources |
| Both CVSS v4 **9.2**, unauthenticated RCE | php.net archive, Google Cloud, GHSA-6wmf | Confirmed |
| Published **2026-10-21** | php.net archive, both GHSAs, Google Cloud | Confirmed |
| Fixed upstream: **8.5.12, 8.4.27, 8.3.36, 8.2.35** | php.net archive, both GHSAs, Google Cloud | Confirmed - matches the prompt's baseline |
| Affected upstream (supported branches): everything **before** those releases | Both GHSAs | Confirmed |
| Affected lower bound **5.4** | Google Cloud ("5.4 through 8.5.11"), Wiz ("back to 5.4") | Third-party only; GHSAs do not enumerate old branches |
| PHP 8.2 EOL 2026-12-31 | php.net archive | Confirmed |
| Updating is the only complete fix; config options are partial | php.net archive, both GHSAs, Google Cloud | Confirmed |
| Vendor backports | Google Cloud: vendors got patches in advance; php.net: "check your distribution" | Confirmed in general; **no per-vendor package versions were collected** (see limitation) |

### Source conflict (unresolved, disclosed in the data)

* php.net: security team published **source-only backports for 7.4, 8.0 and 8.1**.
* Google Cloud: **8.1 and earlier will not be fixed**; upgrade to 8.2+.
* The GHSA pages mention neither.

Decision: treat ≤ 8.1 as *unsupported with no upstream binary release* → "Potentially exposed" unless a distribution marker suggests a vendor-maintained build, and tell the user a backport might exist. The conflict is stored in `knownDiscrepancies` and shown in reports. This must be re-checked before every release.

### What we deliberately did *not* do

* No per-distribution fixed-package table (Debian/Ubuntu/RHEL…). We did not collect or verify those from the vendors' trackers, and inventing them would violate the "do not invent" rule. `vendorBackports.knownVendorAdvisories` is empty, which means *not collected*, never *none exist*.
* No other PHP CVEs. The dataset covers these two only, and says so.

## 2. Existing product: "php2shell Checker" (Eye Security B.V.)

From its Chrome Web Store listing, read 2026-10-23: version 1.0.3.1, updated 2026-10-22; "read-only PHP check" of PHP version, PHP applications and hosting stack from HTTP headers; reports whether the version is vulnerable to the two CVEs; runs only when clicked; privacy label: no data collected. The listing does **not** state its permissions, and I did not inspect its source (and would not copy it).

### Gaps this project addresses

| Gap in a header→badge checker | PHP2Shell Detector |
|---|---|
| Binary vulnerable / not vulnerable | Six evidence-based states; "No indicators" is explicitly not "safe" |
| A version number alone decides | Distro suffix/marker → "backport may apply"; unsupported branches; proxy/CDN reliability downgrade; conflict detection; spoof-aware wording |
| No account of evidence quality | Each item shows source, time, direct vs inferred, reliability + reason, and *what it does not prove* |
| No path beyond headers | Owner-report import (schema-validated; Ed25519 signatures; local trust list) and a companion CLI |
| No staleness handling | Advisory dataset has `lastVerifiedAt` + `maxAgeDays`; stale data downgrades "fixed" readings |
| No exportable result | Redacted JSON + Markdown report |
| Redirects unclear | Final origin reported; cross-host redirects are never assessed as the requested site |

### Things that cannot be reliably established from a browser

* The real PHP version/patch level when headers are hidden, stripped, spoofed or CDN-rewritten.
* Whether a vendor backport is installed.
* Whether long-running workers were restarted after an update.
* Which backend node handled the request.
* Presence of `PHPSESSID` - `Set-Cookie` is a forbidden response header for `fetch`, and reading cookies would need the `cookies` permission, which we refuse on privacy grounds.
* Whether a WAF/CDN actually blocks the attack (a CDN header only shows it is there).
* Server-side configuration mitigations (`memory_limit`, `fatal_error_backtraces`, …). These can only come from owner reports.

## 3. Chrome Web Store guidance

`developer.chrome.com/docs/webstore/best-practices` (read 2026-10-23) covers permissions, the Privacy-tab disclosure (must match the privacy policy) and accurate listings. It defers to the Program Policies for single purpose and remote code; the release checklist (`docs/RELEASE.md`) handles those: single purpose = PHP2Shell exposure assessment, no remotely hosted code (the audit script enforces `script-src 'self'` and no remote scripts).
