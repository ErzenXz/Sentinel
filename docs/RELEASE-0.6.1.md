# Sentinel v0.6.1 — interface redesign

Home now starts with a clear file/folder scan entry and compact protection rows. Scanner and firewall review place the selected item's evidence beside their tables when the window has room. Shared controls and every page use a charcoal navigation rail, warm light workspace, restrained green actions and thin section separators.

- Smaller controls, consistent status chips, pinned Settings and session privilege in the header. Home's latest scan is a compact summary; scanner timing appears below the results.
- Responsive table/inspector layouts, minimum verdict widths, selectable full evidence, useful empty/error states and selection-aware actions.
- Native WPF without new dependencies, web views, image assets or animation loops. Keyboard shortcuts, busy/cancel controls, announcements and dynamic Windows high-contrast resources remain.
- Claude Opus 5.5 implemented the redesign through the requested CLI. The source was reviewed and polished after compilation and visual inspection of the example-data mockup.

The detection engine, API boundaries and server behavior are unchanged. File remediation, firewall confirmations/identity checks, snapshot freshness, AI consent and standard-user gates remain in place.

Verification on macOS: Windows-targeted WPF compilation has zero warnings/errors; 94 core tests and 13 server tests pass. XAML, 50 resource references, named controls, matching brush defaults and selected contrast pairs pass. The browser mockup passes interaction checks and 18 layout checks from 320 to 1200 pixels. Windows x64 and ARM64 self-contained app/CLI packages pass architecture, version, runtime, integrity and checksum checks.

The images are source-based mockups, not native Windows screenshots. Actual Windows rendering, DPI, Narrator, high contrast and OS enforcement remain pending. This remains an unsigned development preview; follow the Windows acceptance matrix.

Older releases remain available. Artifacts use `Sentinel-0.6.1-*` and `SHA256SUMS-v0.6.1.txt`; the previous v0.6 checksum manifest is retained.
