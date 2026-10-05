# Sentinel threat-intelligence server

Self-hostable Node.js 22+ service with no npm runtime dependencies. It publishes signed SHA-256 indicator lists to Sentinel clients. It has no malware-download, file-upload, device tracking, or per-file reputation-query endpoint.

## Start locally

From this directory:

```sh
node cli.mjs init
node cli.mjs serve
```

Default address: `http://127.0.0.1:8787/`. Initialization creates a unique RSA-3072 signing identity, an admin token, and a feed containing the bundled **6,113 ESET public research indicators** plus a harmless demonstration fixture. Never distribute `data/signing-private.pem` or `data/admin-token.txt`.

Copy **only** `data/public.pem` to the Windows PC. In Sentinel → Sentinel engine, set the server URL, import the public key, compare its SHA-256 fingerprint with the server operator, save trust, and update the signed feed. The fingerprint is printed by `init` and available at `/healthz`. Verify it through a trusted channel; downloading a key from an untrusted server does not establish trust.

`127.0.0.1` on a Windows PC refers to that PC. To use a server on another machine, expose it through your HTTPS reverse proxy and use that HTTPS URL in Sentinel. The client permits plain HTTP only for loopback.

## Docker

```sh
docker compose build
docker compose run --rm threat-server node cli.mjs init
docker compose up -d
```

The supplied Compose file binds the service to host loopback, runs as a non-root user, drops capabilities, persists `/data`, and enables ESET metadata refresh every 24 hours. Use `docker compose cp threat-server:/data/public.pem ./public.pem` to retrieve the public key after startup. Configure your own TLS reverse proxy before remote access. Block `/v1/admin/*` at the public proxy and manage the server locally; public clients need only `/v1/feed`, `/v1/public-key`, and `/healthz`.

Container execution was not tested in this macOS environment because Docker is unavailable. The service and real HTTP/client interoperability were tested directly with Node.

## Intelligence sources and refresh

### ESET public research IOCs — no credential required

```sh
node cli.mjs sync-eset
```

This reads the official [ESET malware-ioc repository](https://github.com/eset/malware-ioc), pins one Git commit, downloads only `samples.sha256` text files, validates every line, deduplicates hashes, and publishes a new signed sequence. No malware binaries are fetched. All downloads must succeed before the ESET source is replaced. Curated entries from other sources are preserved. Source files, commit, retrieval date, and the BSD two-clause license are retained in the seed/provenance files. License changes require operator review.

For automatic refresh in direct Node deployments:

```sh
SENTINEL_AUTO_SYNC=eset SENTINEL_REFRESH_HOURS=24 node cli.mjs serve
```

On PowerShell, set these environment variables before `node cli.mjs serve`. Allowed intervals are 6–168 hours; overlapping refreshes are prevented. Failed refreshes retain the previous feed. An expired feed is visible to clients as stale; keep monitoring the server's health. A signed publication date is not a promise of complete or current malware coverage.

### MalwareBazaar — optional authenticated importer

```sh
MALWAREBAZAAR_AUTH_KEY=your-operator-key node cli.mjs sync-bazaar --accept-terms
```

Use your actual operator key without committing it. The importer uses `query=get_recent&selector=100` at the official API and imports metadata only. This recent-100 window is not a full historical malware database; repeated polling can miss additions during gaps. Access and redistribution must comply with [MalwareBazaar's API terms and fair-use conditions](https://bazaar.abuse.ch/api/); commercial usage may require a subscription. No MalwareBazaar data was fetched during development because no operator key was supplied.

### Operator-curated lists

```sh
node cli.mjs import vetted-indicators.json
node cli.mjs import sha256-lines.txt
node cli.mjs remove <sha256>
node cli.mjs allow <sha256>
node cli.mjs publish
```

JSON format:

```json
[{"sha256":"64 hexadecimal characters","label":"Confirmed threat family","source":"Your vetted source"}]
```

Text format: one SHA-256 per line, with optional `#` comment lines. Maximum 100,000 indicators. Invalid imports are rejected as a whole. `remove` suppresses that hash from later upstream reimports; `allow` removes suppression but requires a new import/refresh to restore the rule. Use this workflow to handle false positives. Republishing advances sequence and renews the seven-day validity period; it does not fetch intelligence by itself.

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/v1/feed` | Signed envelope |
| GET | `/v1/public-key` | Public PEM; still requires independent trust verification |
| GET | `/healthz` | Feed status, count, expiry, demo-only indicator, fingerprint |
| POST | `/v1/admin/import` | Bearer token; JSON `{ "hashes": [...] }` |
| POST | `/v1/admin/remove` | Bearer token; JSON `{ "sha256": "..." }` |
| POST | `/v1/admin/allow` | Bearer token; JSON `{ "sha256": "..." }` |
| POST | `/v1/admin/publish` | Bearer token; JSON `{}` |

API mutations require the generated token or `SENTINEL_ADMIN_TOKEN` (at least 32 characters). Browser-origin requests are rejected, body size is bounded, and private files are never served. Run one writer/service instance per data directory; the JSON store is not designed for multiple processes modifying it simultaneously. Back up signing keys and state together. Restoring an old sequence will be rejected by clients; recover with an advanced sequence or deliberate key rotation.

## Harmless end-to-end check

```sh
node cli.mjs demo-text > harmless-fixture.txt
```

Scan this file with a client that loaded the default server feed. It should produce a known-hash match labeled **harmless demonstration fixture**. It is not malware and says nothing about overall detection rates.

Run server tests with `npm test`. From the project root, build `src/Sentinel.Cli` and run `node scripts/verify-engine.mjs` to test actual Node → .NET feed verification and scanning.

## v0.3 source health

`GET /healthz` verifies the stored feed signature and reports `issuedAt`, `ageSeconds`, grouped `sources`, and `refreshes.eset` / `refreshes.malwarebazaar` when an import has been attempted. Refresh records contain the latest attempt/status and last successful fetch/import (`succeededAt`, `imported`); failed attempts retain that success record and the previous signed feed. Exception messages, upstream bodies and keys are not stored in refresh metadata.

Status is `ok`, `expired`, or `inconsistent` when state/feed sequences differ after an interrupted publication. Republish with the same preserved signing key after checking state to recover the latter. An interrupted refresh can retain `running` until the next attempt. Health metadata is operational and unsigned; only the signed feed authorizes client indicators. Feed age and refresh success do not establish malware coverage or source-data freshness. `corpusFreshnessGuaranteed` is always false.
