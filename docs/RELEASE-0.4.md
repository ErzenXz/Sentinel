# Sentinel 0.4.0 — session usability

This unsigned development release adds opt-in tray persistence, private count-only notifications, saved monitoring-folder resume, six-hour signed-feed checks, finding search/verdict filters, history status filters and provider model discovery. All session background preferences start disabled. The app uses system high-contrast resources and wrapping actions; one interactive instance can restore its tray window. Exit waits for active operations to settle after cancellation.

Feed updates/reset are serialized; staged cache writes use unique files and bounded sequence reads. Model discovery lists metadata with strict size/count limits and redirects disabled, preserves manual IDs and never sends security data or calls inference.

Validation: 73 portable core tests, 13 server tests, actual Node-to-CLI signed-feed/ZIP/report/model metadata integration, Windows-targeted WPF compilation and self-contained x64/ARM64 package integrity. See VERIFICATION.md and WINDOWS-ACCEPTANCE.md for the native checks still required. There is no new live indicator snapshot, installed service, kernel driver, packet filter, automatic AI enforcement or comparative performance claim.
