# Roadmap

Nothing below is implemented. Items are ordered by value/risk.

## Near term

* **Advisory refresh without a backend**: ship dataset updates as signed releases; consider an *optional, user-enabled*, signed, static dataset fetched from a documented URL (would add one disclosed external request and its own threat model).
* **Per-distribution fixed-package tables** (Debian/Ubuntu/RHEL/Alpine/SUSE/Amazon Linux) collected from vendor trackers, each with source + date, so "backport may apply" can become "this package string is/was fixed". Not done now because none was verified from primary sources.
* Check additional well-known paths (e.g. a user-supplied path list), still passive and user-initiated, one request each, shown before sending.
* PHP-version fingerprints beyond headers via an **opt-in** content script reading `<meta name="generator">` of the open page (needs a new permission justification).
* Firefox/Edge builds.
* Automated tests against real PHP containers (mod_php, FPM, Debian/Ubuntu packages) in CI to validate header behaviour and false-positive/negative rates; use them to calibrate (or retire) the qualitative confidence label.
* Localised UI.

## Owner verification

* Hardware-key / sigstore-style signing for reports; key rotation and revocation lists.
* `php-fpm` / `apache2` worker start-time collection in the CLI, to evidence "workers restarted".
* Container-image attestation (SBOM → PHP version → package changelog CVE match).
* Report-schema v2 with per-node entries for multi-backend deployments.

## Active testing (out of MVP, intentionally)

An active, non-destructive check would need **before any code is written**: an authorisation model (proof of ownership such as a DNS TXT or well-known file), rate limits, a strictly benign probe design reviewed by someone independent of the author, a kill-switch, and a statement that it will never attempt memory exhaustion, crashes or code execution. Until then the tool stays passive.

## Distribution

* Reproducible-build verification in CI; provenance attestation for release zips.
* Chrome Web Store listing assets and a hosted privacy policy.
