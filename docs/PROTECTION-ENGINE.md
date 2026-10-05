# Sentinel's independent protection engine

The v0.3 engine directly reads local files, calculates SHA-256 using a bounded streaming buffer, and checks a local immutable hash index. It does not call Microsoft Defender or send file hashes/content to a server. The compiled app includes an ESET public research IOC snapshot; a trusted self-hosted server can replace it with a newer signed catalog. The built-in harmless standardized AV test marker is labeled as a test file, not live malware.

## What detection means

- **KnownThreat:** exact hash match to an embedded or cryptographically verified indicator. Evidence includes a label and source. A trusted operator can still publish a mistaken rule; users review remediation.
- **TestFile:** the standardized harmless antivirus test marker.
- **NeedsReview:** document/image-style executable extensions or specific script patterns. These can be legitimate and cannot be quarantined from the UI.
- **NoKnownMatch:** no current rule matched. It is not a clean/safe verdict.
- **Skipped/Error:** the file was not fully inspected. Limits and read errors are counted, not silently treated as safe.

Default bounds are 256 MiB per file, 50,000 filesystem entries, depth 64, and 2,000 retained findings. Exact detections take priority over lower-priority findings when the result list is full. Truncation is explicit. Files are scanned sequentially using pooled buffers returned with clearing; there is no permanent process-per-file overhead or unsafe timestamp-only scan cache. ZIP containers and their contained files are hashed separately; unsupported archive formats receive an incomplete-content finding. Symbolic links, junctions/reparse points, UNC/device namespaces, and alternate data streams are excluded.

## ZIP contents and budgets

The scanner detects ZIP signatures or recognized ZIP-based extensions (ZIP, JAR, APK, NuGet, OOXML, OpenDocument and EPUB). Before using `ZipArchive`, a streaming preflight checks end/central/local records, bounds entry metadata to 4 MiB, and rejects inconsistent boundaries or names. Each streamed entry receives a CRC-32 integrity check before its hash detection is accepted. No extraction API is called. Entry names never become filesystem destinations.

Per outer archive tree, defaults are 2,048 directory entries, 32 MiB per entry, 128 MiB cumulative decompression, 200:1 maximum compression ratio, two nested levels below the outer archive, and 16 MiB per buffered nested ZIP. The worker processes one archive/entry at a time. Expansion counts include nested-container bytes and their contents, including corrupt data already read. Budgets are checked against declared and actual streamed sizes. These are resource bounds, not measured Windows performance guarantees.

Traversal/absolute/ambiguous names, links/special entries, encrypted entries, ZIP64/multipart containers, unsupported compression, RAR/7z/TAR/GZip/CAB/ISO formats, corrupt metadata/content, and exceeded budgets remain skipped/errors. Self-extracting containers and embedded formats outside the recognized signatures/extensions are not fully covered. Documents' macros and semantic behavior are not analyzed. An exact match on the outer container is sufficient to report a detection; it is not expanded further.

`FileFinding.Path` always names a real outer filesystem file. `ArchiveEntry` is a display-only nested entry chain; `Sha256` hashes that entry and `ContainerSha256` binds it to the outer file. Reports count filesystem files in `Scanned`, verified hashed entries in `ArchiveEntries`, outer reads in `BytesRead`, and decompression separately in `ArchiveBytesRead`. Detections can exceed the filesystem-file count. `ScanFileDetailedAsync` preserves all bounded evidence; the scalar API returns the strongest result.

The archive design follows Microsoft's [guidance for untrusted archives](https://learn.microsoft.com/en-us/dotnet/standard/io/zip-tar-best-practices) and uses [ZipArchiveEntry.Open](https://learn.microsoft.com/en-us/dotnet/api/system.io.compression.ziparchiveentry.open?view=net-10.0). It adds its own preflight, CRC verification and explicit coverage results; encrypted extraction is not enabled.

## Signed updates

The client pins the operator's RSA public key and verifies a SHA-256/PKCS#1 signature over exact payload bytes before parsing indicators. Keys under 3072 bits and private-key imports are rejected. Sequence numbers, expiry, future issue times, validity duration, duplicate hashes, lengths, and total size are checked. Equal sequences cannot change content. Anti-rollback state is committed before replacing the cache. A crash can require redownloading a feed; it cannot silently install an older sequence. A changed trust key requires an explicit user review/reset.

Expired authenticated caches still recognize previously listed exact hashes and are marked stale. Server publishing time/expiry is a transport freshness control, not a guarantee that the corpus covers recent attacks. The bundled snapshot is trusted as part of the executable release; these development builds are unsigned, so they do not establish a production code-signing trust chain.

## Quarantine

Only exact known-threat/test detections can be quarantined. For a contained detection, the UI explicitly asks to quarantine the **whole archive**. `ConfirmQuarantineAsync` rescans against the current catalog, checks the entry hash and the recorded outer-container hash, then supplies a filesystem-only finding to the vault. The vault refuses unconfirmed archive-entry findings. Review patterns cannot authorize removal. Sentinel reopens the source exclusively and recomputes its full hash. It creates an AES-256-GCM backup in 64 KiB chunks, authenticating item identity, chunk position, and lengths. Metadata and an end-of-file marker are authenticated. The per-item key is protected with user-scoped Windows DPAPI. Payload, key, and recovery index are flushed before requesting source removal.

On Windows the source is opened with read/delete access and removed through `SetFileInformationByHandle` while the same handle remains locked. A changed file, unavailable delete permission, cancellation before commit, or key-protection failure keeps the source in place. After backup commit, cancellation does not interrupt the small removal transaction. If removal fails, a backup may remain with `SourceRemoved=false`. A crash after deletion but before the final index update can also leave this conservative status; verify the original path manually.

Restoration authenticates and hashes all content before moving it to a new user-chosen path. It never overwrites an existing file and keeps the encrypted backup until explicit deletion. Incomplete or tampered vault content is rejected. This user-mode vault does not resist malicious code running as the same user/admin and is not a universal crash-proof recovery mechanism. Lost DPAPI account/recovery material can prevent recovery after reinstalling Windows.

## Monitoring and scheduled scans

An opt-in `FileSystemWatcher` watches one selected folder while the app is open. It coalesces change events and scans through one 512-path bounded worker queue after writes settle. Generation tracking requeues rewrites that arrive during a previous scan. Debouncing uses each path’s last change time, so already settled queued files do not incur another 500 ms delay. Sentinel storage is excluded before a file is opened. Existing files need an initial manual scan, and directory renames/creation call for a full folder rescan. Dropped/overflow events are surfaced and require a manual rescan. This is best-effort observation after creation/modification; it does not stop execution before a scan or cover the entire system.

Daily scans use Windows Task Scheduler with this user's interactive, limited token and the bundled `Sentinel.Scanner.exe`. The scanner reads a cached signed feed, or uses bundled intelligence when no server profile exists, runs at below-normal priority, writes a local report, and never removes files. Windows may defer battery-powered runs. No continuous Windows service or kernel minifilter is installed.

## Reports and cancellation

Manual and scheduled scans retain the latest 30 reports under `%LocalAppData%/Sentinel/reports`. Cancellation before starting still cancels immediately; cancellation during a running scan returns completed findings with `Canceled=true` and incomplete coverage. The active unfinished file may be absent. Completed archive-entry evidence is retained when an archive is interrupted. Reports are saved using unique same-directory staging and atomic replacement. Import validates the 16 MiB size bound, enums, counts, paths, hashes and entry metadata. A report is historical evidence, never authority to delete a file; remediation always rescans. Imported/exported JSON contains local paths and is not an authenticated audit.

The native UI can query this user’s task with [Get-ScheduledTaskInfo](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtaskinfo). Scanner exit codes are 0 no known match, 1 command failure, 2 exact detections (possibly with incomplete coverage), 3 incomplete/canceled without detections, and 4 review findings. Windows Task Scheduler has additional result codes.

Kernel-enforced on-access blocking, protected services, broad archive-format coverage, behavioral ransomware prevention, tamper resistance, and independent detection certification remain separate future work. Keep Defender's real-time protection enabled during the preview.
