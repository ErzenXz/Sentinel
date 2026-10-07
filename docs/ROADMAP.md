# Roadmap

## Delivered through v0.9

Native Windows UI; independent hash scanning with a bundled public IOC snapshot; self-hostable signed feeds; ESET refresh and optional MalwareBazaar metadata import; conservative review patterns; chunked authenticated quarantine/restore; best-effort folder monitoring; scheduled offline scans; CLI; Defender/Firewall controls; configurable AI explanations; bounded ZIP/nested scanning, whole-container confirmation, retained/importable scan reports and partial cancellation, generation-aware monitoring, schedule status, source refresh health, and security-focused portable/server/interoperability tests. v0.4 adds opt-in tray persistence, count-only notifications, folder resume, six-hour signed-feed checks, finding/history filters, model metadata discovery, high-contrast resources and session/shutdown coordination. v0.5 adds bounded one-shot TCP/profile/process capture, deterministic firewall review, selected-only publisher inspection with identity revalidation, optional Jev typed decisions, a bounded single-flight review cache, native C# hosting informed by fx research, and CLI review/benchmark commands.

v0.6 reorganizes the native WPF interface around scanning, timestamped Windows status and reviewing findings. It adds consistent controls/tables, grouped navigation with pinned Settings, advanced disclosures, direct settings links, selection-aware actions, keyboard shortcuts, screen-reader names/status announcements and bounded UI progress updates. Native Windows visual/accessibility acceptance remains required.

v0.7 adds cooperative pause/resume/cancel, low-impact local/CLI scans, depth-bounded streaming traversal and native metadata use, shared read prefixes, catalog text compaction, streamed/capped report I/O and CLI JSON, reproducible allocation/heap comparisons, and gated tagged-release packaging. Native Windows performance and interaction acceptance remain required.

v0.8 adds initial monitored-folder coverage, coalesced directory/overflow/feed recovery with a five-minute deadline and 30-second cooldown, Low impact background scans, permanent watcher failure handling, a 512-item deduplicated priority inbox, batched UI notifications, and live coverage/omission status. Windows monitoring/GUI/performance acceptance remains required.

v0.9 adds native x64 WPF fixture rendering/interaction gates, both inspector arrangements, a verified scanner-page retention fix, explicit table selection and inherited action text colors. Hardware DPI/text scaling, Narrator, OS protection actions and native ARM64 execution remain acceptance work.

## Next release gates

1. Run the Windows acceptance matrix on x64/ARM64: native rendering, Defender interactions, exclusive handles/deletion, DPAPI recovery, UAC, Task Scheduler, junctions/ADS, policy-managed devices, and failed operations.
2. Sign releases, add installer/uninstaller and a narrowly scoped privileged broker, and secure update integrity/key rotation. Add private vulnerability reporting.
3. Benchmark Windows startup, idle CPU/memory, large/small-file throughput, monitoring bursts, and total overhead alongside Defender and local AI runtimes. Publish repeatable results before comparative claims.
4. Expand threat intelligence with provenance, false-positive review, source health, freshness measurement, revocation distribution, and evaluated content rules. Audit/fuzz the bounded ZIP parser and expand archive formats and evaluated content rules. ZIP64, encrypted and unsupported archive contents remain explicit coverage gaps.
5. Validate accessibility/high-contrast rendering and tray/notification behavior on Windows; evaluate Jev firewall decisions on a labeled corpus, expand native network evidence and add multi-profile encrypted credentials.

## Standalone antivirus work still required

Kernel-enforced on-access protection requires a reviewed, signed minifilter and Windows driver testing, a privileged protected service/broker, reliable execution/file-access interception, cancellation/deadlock handling, safe parsers, trusted updates, tamper resistance, and Security Center integration. Behavioral/ransomware prevention needs carefully evaluated telemetry and intervention rules. Independent false-positive and detection testing is essential.

The current folder watcher is not a substitute for that driver. Keep Defender enabled until these capabilities are implemented and validated. Performance/smarts/detection superlatives remain goals that require measured evidence.
