# Sentinel v0.6.0 — native UI overhaul

The main tasks are easier to find: scan a file or folder from Home, review results in File scanner, and inspect network applications in Firewall. The v0.5 scanner, Jev adapters and protection boundaries remain in place.

- Neutral canvas, white cards, restrained blue actions, consistent 42-pixel buttons/fields, grouped icon-and-label navigation and pinned Settings. The minimum window is 960 × 680; tiles and action rows wrap.
- Home shows timestamped Windows checks, Defender/Firewall/monitor tiles, latest saved scan and visible stale-list information. Unavailable data never becomes an all-clear message.
- Findings use readable verdicts, full selected evidence and SHA-256 copy. History, quarantine, apps and network views have useful empty states; read failures retain visible errors. Selection-specific actions stay disabled until eligible.
- Monitoring, daily scheduling, raw TCP/rules, scanner limits and optional Jev review use disclosures. Everyday preferences, trusted server and provider connections live in Settings. Direct setup links expand and focus their section. Expansion is remembered for the current session.
- Global indeterminate progress and Stop waiting remain reachable while page controls are disabled. Escape requests cancellation; Windows operations may continue independently. Scan progress is coalesced into one pending slot, with a 200 ms UI timer and final flush.
- Keyboard navigation, focus outlines, named fields, page headings and coalesced live status announcements. Ctrl+O scans a file; Ctrl+Shift+O scans a folder; F6 switches navigation/content; arrow/Home/End keys move between navigation buttons.
- Claude Opus 5.5 supplied design guidance and a code review via the user-requested CLI. Its recommendations were checked and selectively applied. No model runtime, additional UI framework or web view is shipped.

Verification: WPF and CLI Release builds have zero warnings/errors; 94 core tests and 13 server tests pass; actual local HTTP feed/CLI/model/Jev interoperability checks pass. Source resource/control and palette contrast checks pass. Self-contained Windows x64/ARM64, source and server packages have version, architecture, integrity and checksum checks.

Native Windows rendering, Narrator, high contrast, DPI, keyboard focus, UAC and OS enforcement still require the Windows acceptance matrix. This unsigned preview remains an exact-hash scanner and Windows security companion. Keep Defender enabled. No new detection coverage, comparative performance or AV certification claim is made.

The v0.5 release archives are retained. v0.6 artifacts use `Sentinel-0.6.0-*` and `SHA256SUMS-v0.6.txt`.
