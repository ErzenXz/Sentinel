# Sentinel

MIT-licensed native Windows security application, with an independent local scanner, self-hostable intelligence server, Windows protection controls, and optional AI explanations.

**v0.11.0 is an unsigned development preview.** Our own engine detects exact known hashes independently of Defender. It is not yet a replacement for a tested full antivirus product; keep Defender's real-time protection enabled. No “best,” “lightest,” or detection-rate claim is established.

## New in v0.11.0

- **More archive coverage:** inspect regular V7/ustar TAR entries, GZIP payloads, TGZ and mixed nested ZIP/TAR/GZIP trees within shared budgets, without extraction. Unsupported extensions, corrupt integrity, unsafe names and limits remain visible as incomplete coverage.
- **Less archive allocation:** nested containers at the depth limit keep their complete hash check without an unused in-memory copy. ZIP preflight reuses bounded name/header scratch space and retains compact value records.
- **Fewer background reads:** automatic and manual signed-feed checks only queue a watched-folder recovery when exact-hash rules are added, replaced or revoked. Identical publications and renewals of expiry, sequence, labels or source text still verify and update trusted state.

[Download v0.11.0](https://github.com/ErzenXz/Sentinel/releases/tag/v0.11.0) · [Release notes](docs/RELEASE-0.11.0.md) · [Performance measurements](docs/PERFORMANCE.md) · [Native Windows screenshots](docs/NATIVE-UI-VERIFICATION.md)

## Included from v0.10.0

Selected-file rescans read current bytes with current intelligence and save history. Signed-feed decoding, indexing and cache comparison reduce temporary allocation; identical envelopes retain their signature/expiry/rollback checks without rewriting cache files. Native resource profiling distinguishes runtime warmup from ordinary hardware measurements.

## Included from v0.9.0

- **No retained scanner pages after navigation:** discarded collection views detach from the finding collection, release their filter/count binding and stop their page timer. A native Windows regression changed from 12 retained views to zero after twelve visits.
- **Correct selection and evidence:** tables require explicit selection, and the selected path, reason and SHA-256 are available together. Selection actions start disabled.
- **Readable action labels:** primary, quiet, destructive and disabled button text follows its actual control color. Native screenshots exposed the earlier dark labels on green primary buttons.
- **Native Windows UI verification:** CI renders every real WPF page at normal and minimum sizes, checks both inspector arrangements, exercises pause/resume/cancel and shutdown, detects binding/layout errors and preserves labeled fixture PNGs. Releases now require this job as well as both architecture builds.

[Download v0.9.0](https://github.com/ErzenXz/Sentinel/releases/tag/v0.9.0) · [Release notes](docs/RELEASE-0.9.0.md) · [Native Windows screenshots, verification and limits](docs/NATIVE-UI-VERIFICATION.md)

## Included from v0.8.0

- **Monitoring covers existing files:** starting or resuming a selected folder now runs a Low impact scan while incoming changes stay queued.
- **Recovery after folder moves and missed changes:** directory-name notifications, watcher overflow, full file queues, changes to signed exact-hash rules and the new Recheck watched folder button request a bounded rescan. Requests coalesce; one worker handles file changes and recovery, with a 30-second cooldown between rechecks.
- **Background work has a time budget:** recovery stops cooperatively after five minutes and retains completed findings. File/archive/count/depth limits and excluded Sentinel storage stay explicit. Live monitoring continues after a recovery deadline. Permanent watcher failures mark monitoring stopped and ask you to restart it.
- **Bounded, batched live findings:** a 512-item worker-to-UI inbox replaces per-finding dispatcher callbacks. Up to 128 findings reach the interface every 200 ms; duplicate pending evidence collapses and exact detections take priority. Omitted findings are counted, and the 2,000-row display cannot replace exact detections with review findings.
- **Live monitoring details:** changed-file counts, queued paths, missed events, omitted display findings and the last recovery's counts/limits update while the page is open. Notifications batch counts only.

[Download v0.8.0](https://github.com/ErzenXz/Sentinel/releases/tag/v0.8.0) · [Release notes](docs/RELEASE-0.8.0.md)

## Included from v0.7.0

- **Pause and resume local scans:** controls stay in the status bar while page controls are disabled. Cancellation works while paused and saves completed findings. Pausing is cooperative; an in-flight read can finish before the next checkpoint.
- **Balanced or Low impact:** choose the speed for this session in File scanner. Low impact yields briefly after 4 MiB read or 32 inspected contents, including archive contents, using the same rules and budgets. The CLI accepts `scan <path> --low-impact`; monitoring and scheduling keep their existing defaults.
- **Less scan bookkeeping:** streaming traversal retains at most 64 active directory levels, with bounded findings. Native enumeration metadata avoids a repeated Windows attribute lookup; every file and its parents are still rechecked before reading. Ordinary prefixes share the read buffer; scripts keep their full 32 KiB review prefix.
- **Smaller catalog and report allocations:** repeated public labels/sources share text within each catalog. Reports and CLI scan JSON stream without a whole-output byte/string copy; the 16 MiB report bound, validation, atomic export and historical-report compatibility remain.
- **Measured core improvements:** on a synthetic Mac ARM64 comparison, report round-trip allocation fell 49.8%, catalog-load retained managed memory 14.3%, and wide-folder allocation 7.9%. Timing varied across runs; these are not Windows working-set measurements. [Method, raw results and tradeoffs](docs/PERFORMANCE.md).
- Tagged previews now publish checked Windows x64/ARM64 packages, source, server and checksums through GitHub Actions after both Windows jobs pass.

[Download v0.7.0](https://github.com/ErzenXz/Sentinel/releases/tag/v0.7.0) · [Release notes](docs/RELEASE-0.7.0.md)

## Included from v0.6.1

- **A complete native redesign:** charcoal navigation, warm light surfaces, restrained green actions, compact status rows and cleaner results. Settings stays pinned; the minimum window remains 960 × 680.
- **Home starts with scanning:** scan a file or folder, review compact Windows protection rows, and open your latest saved scan. Windows readings have timestamps; unknown settings and stale threat lists stay explicit.
- **Results are easier to review:** plain-language verdicts, full selected evidence, copy SHA-256, helpful empty states, and selection-aware quarantine, restore, report and firewall actions.
- Monitoring, scheduling, threat-list details and optional Jev review use expandable sections. Everyday preferences and provider/server connections live in Settings; setup links open the right section directly.
- A global busy indicator and Stop waiting action, keyboard shortcuts, focus outlines, named inputs and coalesced status announcements. Scan progress replaces one pending slot and updates the UI at most five times per second, plus its final flush.

Claude Opus 5.5 implemented the visual redesign through the requested CLI. The UI remains WPF/C#; no Claude runtime is embedded. Native rendering is now checked on Windows x64; broader accessibility acceptance still requires Windows. See [v0.6.1 release notes](docs/RELEASE-0.6.1.md) and [UI design and shortcuts](docs/UI-DESIGN.md).

## Included from v0.5

- **Fast local firewall review** groups bounded TCP evidence by process and flags disabled/unknown profiles, inbound defaults, non-loopback listeners, missing identities and signature issues. One on-demand Windows capture replaces repeated requests; signatures are inspected only for the selected app.
- **Jev structured decisions** through TypeSafe directly or Vercel Gateway's TypeSafe-compatible API. This is a separate optional API-key connection, with a five-second deadline, strict probability validation and a categories/counts preview. User-approved reviews have no model tools or automatic firewall actions.
- A small native review host serializes requests and reuses identical successful decisions for two minutes, with a 128-entry in-memory cap. Failures require manual review and cannot erase local warnings.
- New CLI network snapshot/review and Jev commands, plus a repeatable synthetic local-policy benchmark.

See [firewall review](docs/FAST-FIREWALL.md) and [Jev/fx research](docs/JEV-FX-RESEARCH.md). Sentinel retains its WPF/C# runtime: no JavaScript agent runtime, fx binary, or model weights are bundled.

## Included from v0.4

- Opt-in **close-to-tray**, count-only detection notifications, and resuming your selected monitoring folder when you reopen Sentinel.
- Opt-in **signed-feed checks** immediately and every six hours while the app runs. Checks run sequentially and retain the verified cache on failure.
- Search and verdict filters for findings, plus scan-history status filters. Filtering preserves original evidence and report totals.
- **Model discovery** for Ollama, OpenAI-compatible providers/LM Studio, and Anthropic. Listing uses metadata-only requests; it makes no inference request and sends no security snapshot.
- System high-contrast colors, wrapping action rows, and a single interactive session with tray-window activation. Exit requests cancellation and waits for the active operation to settle.

See [session preferences](docs/SESSION-PROTECTION.md). All new background options start disabled. There is no login startup entry or Windows service.

## Included from v0.3

- **Bounded ZIP/TAR/GZIP content scanning**, including nested archives and ZIP-based documents/packages. No files are extracted to disk. Encryption, unsupported formats, malformed metadata, corrupt CRCs, and budget limits remain explicit incomplete results.
- **Whole-archive quarantine** after user confirmation, a fresh contained detection, and a matching container hash. The encrypted backup restores the entire original archive.
- **Scan reports** page with import/export, automatic retention of the latest 30 manual/scheduled reports, and partial results when a running scan is canceled. File and archive-entry counts are separate.
- **Stronger folder monitoring**: rewrites during a scan are queued again, settled bursts avoid a delay for every file, own storage is excluded before reads, and queue/missed-event counters are visible.
- **Daily schedule status** with next/last run and result codes. Scheduling also works offline with bundled intelligence, without configuring a server first.
- **Server source health**: publication age, source counts, refresh attempts/last success/failure, and detection of interrupted publication state. Failed upstream refreshes preserve the signed corpus and do not record secrets or upstream error bodies.

The v0.2 foundation remains: 6,113 bundled ESET public research indicators with provenance/BSD notice, a self-hostable Node/Docker server, pinned RSA-3072 feeds with expiry/anti-rollback, metadata-only ESET/MalwareBazaar imports, suppression of false positives, streaming local SHA-256, AES-256-GCM/DPAPI quarantine, and a standalone scanner. AI explanations stay optional, with a sanitized sharing preview.

Existing capabilities include Defender quick/full/custom scans and intelligence updates, protection status and threat history, process/publisher/signature inspection, TCP snapshots, reversible outbound app firewall blocks, local activity records, encrypted API keys, and AI connections for APIs, Ollama/LM Studio, Anthropic, and experimental official Codex app-server access.

## Run on Windows

Extract **all files** from the appropriate v0.11.0 Windows archive and open `Sentinel.exe`. The archive includes .NET and `Sentinel.Scanner.exe`; no SDK is needed to run it.

Open **File scanner** to scan a file/folder immediately using the bundled public indicator snapshot. Open **Quarantine** to review backups. Use a standard Windows user session for independent file remediation and AI. Windows Firewall/Defender operations can require Settings → About Sentinel & administrator tools → Restart as administrator. AI and personal-file quarantine/restore are disabled in elevated sessions.

Our scanner reports no-known-match, review, detected, skipped, and error separately. A no-known-match result does not prove safety. ZIP, V7/ustar TAR and GZIP contents are inspected within strict budgets; encrypted, unsupported, over-budget or unreadable contents remain incomplete. Monitoring observes changes after they happen and stops when you exit Sentinel; opt-in tray mode keeps it running after closing the window. Defender continues its own background protection.

## Run your own server

```sh
cd server
node cli.mjs init
node cli.mjs sync-eset
node cli.mjs serve
```

Requires Node.js 22+. Copy only `data/public.pem` to the Windows PC, pin it in Settings → Threat list & trusted server, and download the signed feed. Use HTTPS for a remote server. See [server setup and Docker](server/README.md). The bundled public IOC snapshot needs no server/API key. MalwareBazaar ingestion requires the operator's own key and compliance with its provider terms.

## Build and test

With .NET 10 SDK installed:

```sh
dotnet build src/Sentinel.App -c Release
dotnet run --project tests/Sentinel.Tests -c Release
npm --prefix server test
dotnet build src/Sentinel.Cli -c Release
node scripts/verify-engine.mjs
```

Run `dotnet run --project tests/Sentinel.UiTests -c Release -- --output artifacts/native-ui` on Windows for native interaction checks and PNGs.

The portable engine tests and real HTTP interoperability test run on macOS/Linux too. WPF compiles with Windows targeting enabled; its native UI and OS operations must run on Windows. Use `scripts/publish.ps1 -Runtime win-x64` or `win-arm64` on Windows to package both executables.

## Design and limits

No Electron, embedded browser, telemetry, or bundled LLM. The own scanner uses one worker, pooled buffers, and bounded result queues. Monitoring/schedules are opt-in. Defender, AI runtimes, and the app consume separate resources; Windows performance comparisons have not been made.

A hash list detects exact published files and misses changed/new malware. We do not yet have kernel-enforced execution blocking, broad archive-format coverage, ransomware behavioral blocking, a protected service, or AV certification. These require sustained engineering and independent evaluation.

Read [v0.11.0 release notes](docs/RELEASE-0.11.0.md), [performance measurements](docs/PERFORMANCE.md), [engine design](docs/PROTECTION-ENGINE.md), [AI connections](docs/AI-PROVIDERS.md), [security boundaries](docs/SECURITY.md), [verification](docs/VERIFICATION.md), [Windows acceptance checks](docs/WINDOWS-ACCEPTANCE.md), [roadmap](docs/ROADMAP.md), and [third-party notices](docs/THIRD-PARTY-NOTICES.md).

Sentinel code is MIT licensed. Embedded ESET indicator data remains BSD two-clause licensed; ESET does not endorse Sentinel. No OpenClaw source code or third-party malware binaries are bundled.
