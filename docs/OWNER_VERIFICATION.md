# Owner verification reports

A passive scan cannot see a server's PHP binary. Owners can supply a structured report. The extension **validates it locally**, labels it, and only in tightly defined cases lets it change the assessment.

## Schema (`php2shell-detector/owner-report`, v1)

Validated with zod in `src/verification/schema.ts`; unknown fields are rejected (`.strict()`).

| Field | Notes |
|---|---|
| `target.origin` | Must equal the assessed origin, else the report is rejected |
| `runtime.phpVersion` | Full version, e.g. `8.3.36` or `8.1.2-1ubuntu2.20`; `packageVersion`, `sapi` optional |
| `os` | `{name, version?}` optional |
| `packageSource` | `{type: upstream-source \| distro-package \| vendor-image \| other, name?}` |
| `vendorAdvisoryRef` | https URL |
| `patch.status` | `fixed-upstream` \| `vendor-backport-applied` \| `not-patched` \| `unknown` |
| `patch.workersRestarted` | boolean - are all long-running workers restarted after the change |
| `patch.mitigations` | subset of `memory-limit-unlimited`, `post-size-limit`, `upload-progress-disabled`, `fatal-error-backtraces-off`, `waf-body-limits` |
| `verifiedAt` | ISO-8601 timestamp |
| `provenance` | `{method: cli \| manual, tool?, collectedBy?, commands?}` |
| `signature` | optional `{alg: 'Ed25519', keyId, publicKey, value}` |

## Trust model

* The signature covers the **canonical JSON** (sorted keys, no whitespace) of the report without its `signature` field. The CLI and the extension use the same algorithm (tested for equivalence).
* `keyId` = hex SHA-256 of the raw 32-byte public key and must match the embedded key.
* A **valid signature** proves that the holder of that key signed exactly these bytes. It does **not** prove the content is true. A **trusted** key is one whose fingerprint the user added to the local trust list (`chrome.storage.local`) after verifying it out of band. Trust ≠ truth: the signer vouches for their own server.
* An **invalid** signature rejects the whole report (no silent downgrade to "unsigned").
* A valid signature from an **untrusted** key is shown as `UNTRUSTED` and treated as self-reported.
* Without a signature the report is **self-reported**.

## What each outcome can do

| Report | Effect |
|---|---|
| Invalid schema / wrong origin / invalid signature / future-dated | Rejected; shown with reasons; assessment unchanged |
| Unsigned, or signed by an untrusted key, claiming a patch | Shown as an *unverified claim*; state **not** changed |
| Unsigned/any, listing mitigations and `not-patched`/`unknown` | **Mitigation detected** (labelled self-reported or attested) - explicitly *not patched* |
| Trusted signature + `fixed-upstream` + version ≥ fixed release + workers restarted + ≤ 30 days old | **Patch verified** |
| Trusted signature + `vendor-backport-applied` + `vendorAdvisoryRef` + `packageSource.name` + `packageVersion` + workers restarted + ≤ 30 days old | **Patch verified** |
| Any of the above but the reported base version differs from the public header | **Inconclusive** (conflict) |

The extension never says it inspected the server; the evidence card reads "self-reported" or "attested (signed)".

## Companion CLI

```bash
node tools/php2shell-attest.mjs keygen --out attest-key.json         # prints the fingerprint to trust
node tools/php2shell-attest.mjs report --origin https://example.com \
  --patch-status fixed-upstream --workers-restarted \
  --package-source upstream-source --key attest-key.json --out report.json
```

It runs `php -r 'echo PHP_VERSION;'` / `PHP_SAPI` locally (via `execFile`, no shell), makes **no network requests**, and records the commands run. Patch status and "workers restarted" are asserted by the operator; the CLI cannot measure them. The private key file is written with mode 0600 - keep it off the web server.
