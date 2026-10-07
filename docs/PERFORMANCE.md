# Core performance measurements — v0.7.0

Measured 2026-10-07 on macOS ARM64, .NET SDK 10.0.401/runtime 10.0.12. Baseline is commit `75b3197` (v0.6.1); the same benchmark harness was compiled against the baseline and candidate cores and run sequentially. Each process warms both workloads once, then measures five iterations with collection before each. These are synthetic offline core tests, excluding UI, Windows capture/Defender, AI, startup and real threat classification.

| Workload | v0.6.1 | v0.7.0 | Measurement |
|---|---:|---:|---|
| Load 6,113 bundled indicators | 6,197,152 B | 5,311,832 B | Retained managed-heap delta with forced collection; includes serializer metadata |
| Scan 2,500 × 8 KiB regular files | 18,979,936 B | 17,488,800 B | Median process-wide managed allocations |
| Save + load 2,000 findings with 4,000-character reasons (~8.69 MB JSON) | 34,541,056 B | 17,332,816 B | Median process-wide managed allocations |
| Same folder scan elapsed time | 499.38 ms | 470.22 ms | Median of five warmed runs |
| Same report round trip elapsed time | 24.79 ms | 26.03 ms | Median of five warmed runs |

The report workload allocates **49.8% fewer bytes**; catalog-load retained managed memory falls **14.3%**, and folder allocation falls **7.9%**. Report streaming traded about 1.25 ms of median time for the large allocation reduction in this run. Folder timing improved in the final paired run, but exploratory runs varied in both directions; no broad throughput claim or significance estimate is established. Host/filesystem load, JIT, collection and warm caches affect these small samples.

[Baseline raw output](benchmarks/scanner-baseline-v0.6.1-macos-arm64.json) · [v0.7.0 raw output](benchmarks/scanner-v0.7.0-macos-arm64.json)

## Reproduce

```sh
dotnet run --project tests/Sentinel.Benchmarks -c Release -- --files 2500 --iterations 5
```

The harness creates benign fixtures in a unique directory beneath its build output and removes only that directory in `finally`. Bounds are 1–20,000 files and 1–20 iterations. For the baseline, check out `75b3197` separately, then compile this same harness with `-p:CoreProject=<absolute path to baseline/src/Sentinel.Core/Sentinel.Core.csproj>`. Run comparisons sequentially on an otherwise quiet host. The candidate adds two small report metadata fields; the JSON size differs by roughly 53 bytes.

## Resource controls

- One worker; no file-result timestamp cache. Every file is freshly opened and hashed. Streaming traversal holds one enumerator per active directory level, at most 64; a flat directory needs one. The 50,000-entry, 2,000-finding and archive budgets remain.
- Ordinary files retain up to 128 prefix bytes inside the pooled 64 KiB read buffer, outside subsequent reads. Scripts retain the original 32 KiB review prefix in a separate cleared pool buffer. Known ZIP extensions keep stream buffering for archive parsing. Filename checks use spans and ordinal case-insensitive comparisons.
- Repeated indicator label/source strings are shared inside a single catalog, preserving exact text, order and hashes. No global string interning or unbounded cross-feed cache is used.
- Report serialization/deserialization use 64 KiB JSON buffers and a counting stream with a 16 MiB read/write ceiling. Oversized or canceled exports remove staging and retain the prior destination. Loaded findings are still validated before use; historical evidence is rechecked before quarantine.
- Pause uses an asynchronous signal with cancellation rather than polling. Checkpoints occur between filesystem entries, read chunks, ZIP headers and entries. Low impact yields 20 ms per 4 MiB read and per 32 inspected contents. It is intended to trade throughput for opportunities for other work, not reduce detection coverage. It does not pause Defender, monitoring, or providers, and retains current file buffers/handles while paused.

Windows enumeration already contains file attributes in the [.NET Windows implementation](https://github.com/dotnet/runtime/blob/v10.0.1/src/libraries/System.Private.CoreLib/src/System/IO/Enumeration/FileSystemEntry.Windows.cs); Sentinel uses them for traversal while freshly checking each leaf/parent before opening content. Concurrent filesystem changes can still yield incomplete results requiring a rescan.

Real Windows startup, idle working set/CPU, peak memory, archive throughput, network capture and overhead alongside Defender/local AI still need measurement on x64 and ARM64. Managed allocation/heap estimates are not process working set, and this comparison does not establish antivirus detection quality or comparative product rankings.

## v0.8 monitoring bounds and scan regression check

Monitoring now checks existing files and recovers directory moves/overflow/feed updates through one worker. Recovery requests retain one pending bit; the file dictionary and channel retain at most 512 paths/items each. Rechecks wait at least 30 seconds after the previous recovery finishes and have a five-minute cooperative scan deadline. Completed findings are delivered in batches of 128, with 200 ms between large batches. The native app uses Low impact scans and drains at most 128 inbox findings every 200 ms. The inbox holds at most 512 deduplicated findings and prioritizes exact detections; the visible list holds at most 2,000. Unresponsive UI, full queues, scan limits and excluded storage remain explicit coverage gaps, never complete protection claims. Recovery reports are not retained as background history.

Portable tests exercise 160,000 concurrent inbox additions, bounded overflow during a paused initial scan, populated directory moves, rewrites, cooldown coalescing while new-file scanning continues, time-budget cancellation, storage boundaries, observer failures and idempotent shutdown. They prove data-structure bounds/behavior, not Windows peak working set or responsiveness.

The same benchmark harness/output directory was compiled first against tag `v0.7.0` (`e72f498`), then the v0.8 candidate. The two warmed five-iteration runs were sequential on the same Mac ARM64/.NET 10.0.12 setup as above, using equal-length unique fixture paths. Baseline cores use the existing `CoreProject` override; do not move the harness into a deeper directory for comparisons, since longer file paths increase scan allocations.

| Managed-memory measure | v0.7 baseline | v0.8 candidate |
|---|---:|---:|
| Folder workload median allocated bytes | 17,488,800 | 17,488,816 |
| Report round-trip median allocated bytes | 17,327,600 | 17,265,256 |
| First catalog-load retained managed bytes | 5,327,736 | 5,327,736 |

Folder allocations differ by 16 bytes; these samples show no material regression in the existing offline core workloads. The small report/timing differences do not establish a new performance gain. This check excludes active monitoring, WPF, Defender and Windows memory; the new background work deliberately adds reads for initial coverage and recovery.

[v0.7 baseline raw output](benchmarks/scanner-baseline-v0.7.0-macos-arm64.json) · [v0.8 raw output](benchmarks/scanner-v0.8.0-macos-arm64.json)


## v0.9 native scanner-page retention

A Windows Server 2025 x64 / .NET 10.0.12 fixture run found that all twelve scanner collection views remained alive after twelve page visits and forced collection. Managed heap grew from 9,196,032 to 13,936,168 bytes during that sequence. Each view subscribed directly to the window-lifetime finding collection and retained its filter/page objects. The app now clears its table/count binding/filter and detaches the old view on navigation and shutdown; its page timer also stops explicitly.

The passing candidate retained **zero of twelve** old views. Its managed heap was 5,666,520 bytes before and 5,476,232 afterward. These readings diagnose the leak; they are not a controlled percentage comparison of overall process RAM. The baseline normal-width window was clamped by the hosted display to 1044 × 788; the final harness enforces 1200 × 820 and also tests 960 × 680. Harness assertions/captures increased while addressing those verification limits. Retention counts are the regression gate; warm caches, GC, fixture layout and process working set are separate.

The candidate's three-second hosted software-rendered fixture sample consumed 2,546.875 ms process CPU with a 161,837,056-byte working set, 67,452,928 private bytes and 6,568,608 managed bytes. Only one ApplicationIdle dispatcher operation ran during that sample. The high CPU result needs investigation/measurement on ordinary Windows hardware; its cause is not established. The test forces software rendering and follows many render-to-bitmap captures, so this is neither an ordinary production idle measurement nor evidence of an idle CPU improvement. No Windows throughput, whole-process memory-saving percentage or comparative AV claim is made.

[Baseline raw native output](benchmarks/native-ui-baseline-v0.8-windows-x64.json) · [First passing candidate raw output](benchmarks/native-ui-first-passing-windows-x64.json) · [v0.9 candidate raw output](benchmarks/native-ui-v0.9-windows-x64.json) · [Native method and limitations](NATIVE-UI-VERIFICATION.md) · [First passing candidate job](https://github.com/ErzenXz/Sentinel/actions/runs/37641620009)


## v0.10 signed-feed refresh allocations and Windows CPU investigation

The unchanged-feed workload uses 10,000 distinct harmless indicators in an approximately 2.03 MB signed envelope. Signing, fixture creation and one warmup update happen before five measured refreshes. Each refresh still verifies the signature, expiry, sequence and indicators and compares all committed cache bytes. The fake HTTP handler returns the envelope in memory; these timings exclude network latency and server work.

The same v0.10 harness was built against the v0.9 tag (`af4ce1b`) and candidate core (`903b2ee`), then run sequentially from the same harness/output directory. Windows measurements ran on one Windows Server 2025 x64 hosted runner with .NET 10.0.12; Mac measurements used macOS ARM64/.NET 10.0.12. Synthetic envelope signatures/timestamp precision vary a few bytes between processes; indicator count/text and verification checks are equal. Five warmed iterations are a small sample; timings vary with filesystem/JIT/host activity and are not a significance estimate.

| Host / unchanged signed-feed refresh | v0.9 managed allocations | v0.10 managed allocations | Reduction | Median time, baseline → candidate |
|---|---:|---:|---:|---:|
| Windows x64 | 21,072,704 B | 10,117,448 B | 52.0% | 35.6681 → 38.1747 ms |
| Mac ARM64 | 21,092,112 B | 10,129,688 B | 52.0% | 25.5387 → 19.4201 ms |

An earlier candidate before cache-loss hardening measured 46.4624 → 26.7132 ms on Windows; the final comparison above reverses that timing direction. Allocation savings persist, but **elapsed-time improvement is not consistent across these runs**. [Earlier baseline](benchmarks/feed-before-hardening-baseline-v0.9-windows-x64.json) · [Earlier candidate](benchmarks/feed-before-hardening-v0.10-windows-x64.json). No general speed or CPU improvement is claimed.

These are process-wide **allocated managed bytes for this refresh workload**, not peak memory, retained heap or a 52% reduction in overall application RAM. Windows folder-scan allocations remain essentially equal (8,501,912 → 8,502,928 B), as do report round trips (17,169,584 → 17,168,664 B); no new general scanner-throughput claim is established.

The download uses its existing memory buffer rather than a second envelope copy. A declared Content-Length above the 24 MiB ceiling is rejected before allocation; actual streamed bytes retain that ceiling even when the header is missing or misleading. Base64 bytes decode directly from UTF-8 through the [runtime's byte-array JSON converter](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Text.Json/src/System/Text/Json/Serialization/Converters/Value/ByteArrayConverter.cs), avoiding a large UTF-16 payload string. The validation dictionary becomes the compacted catalog index, avoiding a separate duplicate-key set/index. Equal-sequence cache comparison uses a cleared pooled buffer and an open, freshly validated regular local path. Identical fully verified envelopes skip cache/sequence replacement and disk flushes; changed equal-sequence content still fails. A 32-byte digest from RSA signature verification preserves active payload identity across cache loss. An active verified catalog can rebuild identical missing cache bytes; after restart, a known sequence with no cache requires a newer publication, preserving rollback state.

[Windows baseline](benchmarks/feed-baseline-v0.9-windows-x64.json) · [Windows candidate](benchmarks/feed-v0.10-windows-x64.json) · [Mac baseline](benchmarks/feed-baseline-v0.9-macos-arm64.json) · [Mac candidate](benchmarks/feed-v0.10-macos-arm64.json) · [Paired Windows workflow](https://github.com/ErzenXz/Sentinel/actions/runs/37650862516)

Reproduce the candidate on Windows or Mac:

```sh
dotnet run --project tests/Sentinel.Benchmarks -c Release -- --files 2500 --iterations 5 --feed-indicators 10000
```

For the baseline, compile this same harness with the existing `CoreProject` override pointing to `v0.9.0/src/Sentinel.Core/Sentinel.Core.csproj` in a separate source checkout/snapshot. Keep the harness/output directory the same and run sequentially. The diagnostic workflow fetches exactly that tag and archives only the baseline core, shared build properties and public seed metadata.

### The earlier high fixture CPU reading

The diagnostic harness samples only its own process and threads, with fresh default/software rendering preferences, a 27-bitmap capture burst, hidden/showing windows and the original post-verification phase. Thread descriptions, native start modules, process CPU and dispatcher activity are recorded. This is test-only code and adds no profiler or sampling thread to the shipped app.

In the final Windows run, the original three-second post-verification sample consumed **2,625 ms process CPU**. That entire measured delta was attributed to the existing `.NET Tiered Compilation Worker` thread starting in `coreclr.dll`; only one ApplicationIdle dispatcher operation ran. The later visible/hidden/post-capture five-second samples consumed **0–15.625 ms**. A separate fixture process with `DOTNET_TieredCompilation=0` consumed **0 ms** in the original sample. Together these measurements identify background optimizing JIT warmup as the cause of this reproduced fixture spike. [Microsoft describes tiered compilation's background optimization and configuration](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/compilation).

Production keeps the runtime default. Disabling tiered compilation changes startup/optimization tradeoffs, so the diagnostic process is not a shipped CPU or RAM improvement. Fresh default-rendering first-phase CPU was 343.75 ms / five seconds in this run, then 15.625 ms after the capture burst; new/exited threads and CPU counter quantization can leave thread deltas unattributed. These measurements do not establish ordinary hardware startup/idle requirements, whole-process memory savings, detection performance or antivirus rankings. They exclude production PowerShell status reads, Defender, active monitoring, AI and driver work.

[Fresh default raw report](benchmarks/resource-v0.10-default-fresh-windows-x64.json) · [Fresh software](benchmarks/resource-v0.10-software-fresh-windows-x64.json) · [After verification](benchmarks/resource-v0.10-software-after-verification-windows-x64.json) · [Diagnostic tiered-compilation-off process](benchmarks/resource-v0.10-software-without-tiered-compilation-windows-x64.json)

## v0.11 archive allocations

The same warmed harness compares v0.10 and v0.11 sequentially in the same output directory, with signing/archive creation outside measurement and five forced-collection iterations per workload. Existing ordinary folder/report/unchanged-feed workloads remain included. New ZIP workloads assert identical complete entry/byte counts, no detections and the same explicit depth-limit gap; both versions inspect the full nested-container hash. The many-entry archive has 1,024 × 512-byte files with 128-byte entry comments. The depth-limited archive contains an 8 MiB stored nested ZIP at `MaxArchiveDepth: 0`.

| macOS ARM64 workload | v0.10 allocated bytes | v0.11 allocated bytes | Reduction |
| --- | ---: | ---: | ---: |
| ZIP, 1,024 small entries | 2,337,256 | 1,755,784 | 24.9% |
| 8 MiB nested ZIP at depth limit | 8,578,192 | 123,712 | 98.6% |

The first change comes from reused preflight scratch, compact value headers and span-based name checks; the second removes an 8 MiB copy that cannot be expanded at the configured depth. Buffers retained by the runtime pool, peak/retained heap and working set are not measured. A 98.6% allocation reduction for this workload is not a 98.6% reduction in app RAM. Folder/report/feed allocation differences are small; elapsed times are not general throughput claims. The Windows hosted-runner results below confirm the allocation changes; ordinary hardware working-set/startup/idle/throughput and total Defender/AI overhead remain unmeasured.

[Mac baseline](benchmarks/archive-baseline-v0.10-macos-arm64.json) · [Mac candidate](benchmarks/archive-v0.11-macos-arm64.json)

| Windows x64 workload | v0.10 allocated bytes | v0.11 allocated bytes | Reduction | Baseline/candidate median ms |
| --- | ---: | ---: | ---: | ---: |
| ZIP, 1,024 small entries | 2,340,640 | 1,755,016 | 25.0% | 60.7266 / 57.2398 |
| 8 MiB nested ZIP at depth limit | 8,572,008 | 117,456 | 98.6% | 54.6048 / 51.2994 |

Ordinary Windows folder allocations changed 8,501,944 → 8,523,520 bytes (+0.3%); report 17,168,664 → 17,168,720 and unchanged-feed refresh 10,117,488 → 10,117,816 are effectively unchanged. The new 512-byte TAR prefix uses space within the existing read buffer, rather than another array. Archive timing medians are samples from this runner; no consistent or general throughput improvement is claimed. The 8 MiB removal materially reduces temporary allocation at a configured coverage limit, with the same explicit omitted-content notice. Default nested inspection remains supported within its existing memory budget.

[Windows baseline](benchmarks/archive-baseline-v0.10-windows-x64.json) · [Windows candidate](benchmarks/archive-v0.11-windows-x64.json) · [Paired Windows workflow](https://github.com/ErzenXz/Sentinel/actions/runs/37656744317). The measured Windows core is `63e98e7`; Mac measurements used `2e16fab` before the GNU recognition/committed-recovery correction. Both retained identical benchmark coverage; these subsequent corrections do not remove further read/hash checks. UI footer and documentation updates are outside these core workloads. Full fixture CPU/memory samples remain diagnostic; production tiered compilation stays enabled.
