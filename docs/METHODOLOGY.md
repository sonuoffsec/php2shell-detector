# Detection methodology and known limitations

The assessment is a **deterministic rules engine** (`src/assessment/engine.ts`). Given the same evidence and advisory data it always produces the same state and the same rule ID. No machine learning, no hidden scoring.

## Pipeline

1. **Target handling** (`src/scanner/target.ts`). Only `http:`/`https:`; embedded credentials rejected; a bare host defaults to `https`; IDN → punycode; the path, query and fragment are discarded - the **exact origin** is what is assessed.
2. **Collection** (`src/scanner/collect.ts`). One `GET <origin>/` with `credentials: 'omit'`, `cache: 'no-store'`, `referrerPolicy: 'no-referrer'`, 10 s timeout. The body is cancelled unread. Headers are reduced to an allowlist and scrubbed (`src/privacy/redact.ts`). Redirects are followed by the browser and reported.
3. **Fingerprinting** (`src/scanner/fingerprints.ts`): `PHP/x.y.z` in `X-Powered-By` or `Server`; distribution markers; CDN/proxy headers; WordPress/Drupal/Magento header fingerprints.
4. **Advisory correlation** (`src/advisories`): version compared with per-branch fixed releases. Pre-releases of a fixed version count as *below* it.
5. **Owner overlay** (`src/verification`): an imported report may raise the finding to *Patch verified* or *Mitigation detected* under strict conditions.

## Rules (the `ruleId` shown in every result)

| Rule | Condition | State |
|---|---|---|
| R01 | Request failed / timed out | Inconclusive |
| R02 | Redirect changed the **host** | Inconclusive (destination not assessed as the requested site) |
| R03 | Redirect changed scheme/port only | continues, with a warning |
| R04 | Different base versions in different headers | Inconclusive (conflict) |
| R05 | PHP version string present but unparseable | Inconclusive |
| R06 | Version seen but advisory data unavailable/invalid | Inconclusive |
| R08 | Supported branch, version < fixed release, no distro marker | **Potentially exposed** |
| R09 | Branch < 8.2 and ≥ 5.4, no distro marker | **Potentially exposed** |
| R10 / R11 | As R08 / R09 but a distro marker is present (backport may apply) | **Exposure indicators detected** |
| R12 | Only the branch is disclosed (e.g. `PHP/8.3`) | Exposure indicators detected |
| R13 | Branch < 5.4 (outside the advisory's stated range) | Exposure indicators detected |
| R14 | Version ≥ fixed release (or newer branch) and advisory data fresh | No indicators detected |
| R15 | As R14 but advisory data stale/unavailable | Inconclusive |
| R16 | PHP named / PHP-app fingerprint but no version | Exposure indicators detected |
| R17 | HTTP 5xx/403/429 and no PHP indicators | Inconclusive |
| R18 | CDN/proxy responded; no PHP indicators | Inconclusive |
| R19 | Nothing found, no proxy | No indicators detected |
| O01 | Owner attestation credited (see below) | **Patch verified** |
| O02 | Owner reports mitigations, not patched | **Mitigation detected** (self-reported label shown) |
| O03 | Trusted patch claim contradicts the public version | Inconclusive |

A missing version is never guessed: it yields R16 (PHP is evidently there, level unknown), R18 or R19 depending on what else is visible.

### Which states can be reached how

| State | Passive only | Needs owner verification |
|---|---|---|
| Potentially exposed | yes (R08, R09) | – |
| Exposure indicators detected | yes (R10–R13, R16) | – |
| No indicators detected | yes (R14, R19) | – |
| Inconclusive | yes | – |
| Mitigation detected | no (a CDN header proves nothing about mitigation) | yes (O02; self-reported unless signed) |
| Patch verified | no never | yes **only** a valid signature from a key the user has trusted (O01) |

## Evidence model

Every item records: what was observed, where (`source`), when, `directness` (`direct` / `inference` / `self-reported` / `attested`), `versionProvenance` (`observed` / `inferred` / `admin-supplied` / `attested`), `reliability` + reason, and `doesNotProve`.

Reliability rules: passive header evidence is **never** "high" (headers are administrator-controlled). `medium` normally; `low` when a CDN/proxy is detected, when inferred from an application fingerprint, or when self-reported. `high` only for locally observed facts (status code, redirect) and trusted attestations.

## Confidence

There are **no percentages**. `confidence` is a three-level label:

* `high` - only for *Patch verified*: signed by a trusted key, consistent with advisory data and public evidence.
* `medium` - only for *Potentially exposed* when there is a direct version header, **no** CDN detected, and advisory data is fresh.
* `low` - everything else (absence of indicators, inconclusive, backport-possible, proxy, stale data, self-reported).

Inputs: assessment state, presence of a proxy, advisory staleness, evidence reliability. The label is validated only by the unit tests in `tests/unit/engine.test.ts` and `verification.test.ts`; it has **not** been calibrated against ground truth (no labelled corpus exists), so treat it as a guide to reading the evidence, not a measurement.

## Advisory rules - provenance

See `docs/RESEARCH.md` and `src/advisories/data/php2shell.json`.

| Rule | Source | Checked | Scope | Limitation |
|---|---|---|---|---|
| Fixed 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; earlier on those branches affected | php.net archive; GHSA-w8hw-w9fx-j79w; GHSA-6wmf-4rv5-p3rp; Google Cloud | 2026-10-23 | CVE-2026-109618, CVE-2026-109619 | Upstream releases only; vendor builds may differ |
| Branches 5.4–8.1 affected / unfixed upstream | Google Cloud, Wiz (not the GHSAs) | 2026-10-23 | same | Third-party scope; php.net mentions source-only backports without versions |
| Mitigations (partial) | php.net archive, GHSAs, Google Cloud | 2026-10-23 | same | Reduce risk only |

## Known limitations and failure modes

* **False negatives**: PHP with `expose_php=Off` and no app headers → "No indicators detected" although PHP runs. A CDN that strips headers → Inconclusive at best. A site where `/` is served by a static frontend but `/app/` runs PHP.
* **False positives**: a stale or decoy `X-Powered-By` (e.g. a honeypot); a header from a cache that predates an upgrade; a package with an unrecognised vendor suffix patched under an old version; a CLI-only old PHP while the web SAPI is new.
* **Spoofing**: anything in a header can be forged. Conflicting headers yield Inconclusive, but consistent forged headers cannot be detected.
* **Redirects**: the browser follows redirects before the extension can inspect them. Without access to the destination host, the response is withheld from the extension and the scan reports a failure; with access, the destination's headers are discarded for the verdict (R02) and the redirect is shown.
* **Only `/` is requested.** Other paths/vhosts may run different stacks.
* **Advisory freshness**: the dataset is bundled, not fetched (no backend by design). It goes stale after 30 days and the UI says so; updating needs a new release.
* **Ed25519**: signature verification needs a Chrome with WebCrypto Ed25519 (the manifest sets `minimum_chrome_version` accordingly); otherwise a signed report is shown as *unverifiable* and not credited.
