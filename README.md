# PHP2Shell Detector

> **Detect exposure. Verify the evidence.**

A Chrome extension that checks whether a website shows signs of being exposed to **PHP2Shell**, the critical PHP vulnerabilities [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35).

It does not just show a red or green badge. For every result it shows what was observed, where it came from, how much to trust it, and what it **cannot** prove.

It is passive and safe to run: one normal request to the site you choose, headers only. It never sends exploit payloads, never tries to run code, never crawls, and never sends your data anywhere.

| Result with evidence | Owner-verified result |
|---|---|
| ![Potentially exposed](docs/screenshots/01-potentially-exposed.png) | ![Patch verified](docs/screenshots/05-patch-verified.png) |

Use it only on websites you own or are authorised to assess.

## Install

You need Google Chrome 137 or newer. Other Chromium browsers (Edge, Brave) were not tested.

### Option A: download the ready-made zip (easiest)

1. Go to the [latest release](https://github.com/sonuoffsec/php2shell-detector/releases/latest) and download **php2shell-detector-0.1.0.zip**.
2. Unzip it into a folder you will keep, for example `Documents/php2shell-detector`. Chrome reads the extension from this folder, so don't delete it.
3. In Chrome, open `chrome://extensions`.
4. Turn on **Developer mode** (top right).
5. Click **Load unpacked** and select the unzipped folder (the one that contains `manifest.json`).
6. Click the puzzle-piece icon in the toolbar and pin **PHP2Shell Detector**.

Chrome will say the extension can "read and change your data on all websites". It needs that to read the response headers of whichever site you type. It only contacts a site when you click **Assess website**.

### Option B: build from source

You need Node.js 20 or newer.

```bash
git clone https://github.com/sonuoffsec/php2shell-detector.git
cd php2shell-detector
npm ci
npm run build
```

Then load the `dist/` folder with **Load unpacked** as in steps 3 to 6 above.

## How to use it

1. Open the website you want to check, then click the extension icon. Its address is filled in for you. You can also type any `http://` or `https://` address.
2. Click **Assess website**.
3. Read the result at the top:

| Result | What it means | What to do |
|---|---|---|
| **Potentially exposed** | The site announces a PHP version older than the fixed release for its branch, and nothing suggests a vendor patch. | Ask the host or admin to confirm the real PHP version and update to a fixed release, then restart PHP. |
| **Exposure indicators detected** | PHP is probably in use, but the version is hidden, only partly shown, or looks like a distribution build that may already carry a backported fix. | Verify with the host or the distribution's security notes. Use owner verification (below) if you run the site. |
| **Mitigation detected** | An owner report says protective settings are in place but PHP is not patched. | Treat as risk reduction only. Updating PHP is the only complete fix. |
| **Patch verified** | A signed report from a key you trust says the site is patched. | Nothing more, but remember the signature proves who signed, not that it is true. |
| **Inconclusive** | The evidence is missing, conflicting, or blocked (error page, CDN hiding the server, redirect to another site). | Look at the evidence list, or ask the owner for a report. |
| **No indicators detected** | No PHP clues, or the announced version is already a fixed release. | This does **not** mean safe. PHP can run with its version hidden. |

4. Open **Evidence collected** to see each observation, its source, its reliability and what it does not prove.
5. Open **Remediation and verification** for concrete next steps and commands.
6. Open **Export report** to save a JSON or Markdown report. Cookies, credentials and page content are never included.

### If you own the site: owner verification

A public scan cannot see the server's real PHP binary. You can prove more by importing a report from your own server:

1. On the server, create a signing key and a report with the included script:
   ```bash
   node tools/php2shell-attest.mjs keygen --out attest-key.json
   node tools/php2shell-attest.mjs report --origin https://your-site.example \
     --patch-status fixed-upstream --workers-restarted --package-source upstream-source \
     --key attest-key.json --out report.json
   ```
2. Run an assessment of your site in the extension, open the **Owner verification** tab and add your key fingerprint under **Trusted signing keys** (the keygen command prints it).
3. Paste or upload `report.json` and click **Validate & apply**.

Only a valid signature from a key you trust, plus a restart confirmation and a version that matches the fixed releases, gives **Patch verified**. Details are in [docs/OWNER_VERIFICATION.md](docs/OWNER_VERIFICATION.md).

## Good to know

* A hidden version is never guessed. The tool says Inconclusive or Exposure indicators instead.
* Many sites hide PHP, so a clean result is weak evidence. PHP only shows its version when a PHP page answers, so a static home page or an error page reveals nothing.
* Distribution packages (Debian, Ubuntu, Red Hat and others) often keep an old version number while carrying the fix, so a version alone never proves a site is vulnerable.
* The built-in advisory data was checked on 2026-10-23 and the extension warns when it is more than 30 days old. New advisory data arrives with new releases.
* Full list of limits: [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Privacy

* One request per assessment, to the site you chose, with no cookies, no credentials and no referrer. Only the response headers are read.
* No backend, account, analytics or tracking. Everything runs in the popup on your computer.
* Settings, the key fingerprints you trust and an optional history are stored only in your browser, and you can delete them from the extension.
* Policy: https://sonuoffsec.github.io/php2shell-detector/privacy-policy.html

More detail: [docs/PRIVACY.md](docs/PRIVACY.md).

## For developers

```bash
npm run typecheck
npm test                    # unit and integration tests (100+ tests, local servers)
npm run build               # release bundle and audit (scripts/check-dist.mjs)
npm run test:e2e            # real Chrome with the built extension
npm run screenshots         # regenerate docs/screenshots and store/screenshots
npm run package             # build, audit and write php2shell-detector-<version>.zip
```

End-to-end tests build `dist-e2e/` (the same code as release, plus a throwaway manifest key, a test name and loopback-only host permissions) and drive the popup with Playwright against local servers only.

```bash
npx playwright install chromium    # once
export P2S_CHROME="/path/to/chrome"   # optional, to use a specific browser
npm run test:e2e
```

| Path | Purpose |
|---|---|
| `extension/static/` | `manifest.json` (Manifest V3) and icons, copied into `dist/` |
| `src/popup/` | React user interface |
| `src/scanner/` | URL handling, the single request, header fingerprints |
| `src/advisories/` | Validated advisory data (`data/php2shell.json`) and version rules, separate from the scanner |
| `src/assessment/` | Rules engine and guidance |
| `src/verification/` | Owner report schema, signatures, evaluation |
| `src/reports/` | JSON and Markdown export |
| `src/privacy/` | Header allowlist and redaction |
| `tests/` | `unit/`, `integration/` (real local HTTP servers), `e2e/` (Playwright) |
| `tools/php2shell-attest.mjs` | Administrator command line tool |
| `docs/` | Research, methodology, threat model, privacy, release checklist, roadmap |

Documentation: [research](docs/RESEARCH.md), [methodology and limits](docs/METHODOLOGY.md), [threat model](docs/THREAT_MODEL.md), [privacy and permissions](docs/PRIVACY.md), [owner verification](docs/OWNER_VERIFICATION.md), [Chrome Web Store checklist](docs/RELEASE.md), [roadmap](docs/ROADMAP.md).

### What was and was not tested

Passing at the time of writing (2026-10-23, Windows 11, Node 24, Chromium via Playwright): strict typecheck, the unit and integration tests, the production build and bundle audit, 7 end-to-end tests in real Chromium, and a run against the official `php:8.3-apache` and `php:8.1-apache` Docker images (results in [docs/METHODOLOGY.md](docs/METHODOLOGY.md)).

Not tested automatically:

* The real toolbar popup: filling the address from the active tab and Chrome's install-time permission warning. Automation can load the extension but cannot click the toolbar icon.
* PHP-FPM behind nginx, distribution packages and CDN-fronted sites. These use synthetic fixtures only.
* Chrome Web Store submission.
* The confidence label is qualitative and has not been calibrated against real data.

## Licence

MIT. See [LICENSE](LICENSE). The logo in `logo/` is a separate asset; see the branding note in [docs/RELEASE.md](docs/RELEASE.md) before reusing it.
