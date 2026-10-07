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
