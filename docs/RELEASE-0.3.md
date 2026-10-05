# Sentinel 0.3.0 — 2026-10-05

This release advances the independent protection engine and its day-to-day operation. It remains an unsigned Windows development preview.

- Stream-scan bounded ZIP trees, recognized ZIP documents/packages and nested containers. Preserve outer/entry identity and verify ZIP CRC-32. Never extract files; report skipped/error coverage for unsafe names, links, encryption, corruption and exhausted budgets.
- Quarantine a whole archive only after explicit user confirmation and fresh entry/catalog/container checks. Restore the complete encrypted backup; refuse changed containers and revoked detections.
- Add a native Scan reports page, import/export, latest-report reload, 30-report history and completed findings from canceled scans. Harden report bounds and atomic writes with unique staging paths.
- Fix folder-monitor rewrites lost during an older scan, debounce by last-change time, exclude own storage before reads, expose counters and make disposal repeatable. Monitoring still ends when the app closes.
- Show the current user's daily task state/next/last run/result. Allow offline schedules using the bundled catalog without a server profile.
- Add source refresh health to the self-hosted server: age, source counts, last attempt/success/failure, no secret/error-body retention, and state/feed consistency checks. Continue serving the prior signed corpus on failed imports.

Existing local data, signing keys, cached feeds, encrypted quarantine format and v0.2 JSON reports remain compatible. Extract the whole new Windows package into a stable folder; an existing scheduled task still points at its previous executable path until re-registered. Server code can be updated while preserving its private `data` volume; use one writer, as before. Upstream/production Docker execution remains to be accepted on the target host.

Default limits: 256 MiB outer file, 50,000 filesystem entries, 2,000 findings; per archive tree 2,048 entries, 32 MiB per entry, 128 MiB expansion, 200:1 ratio, two nested levels and 16 MiB per buffered nested archive. Limits constrain work and do not establish comparative performance.

See VERIFICATION.md for performed checks and WINDOWS-ACCEPTANCE.md for native checks still required. Defender should remain enabled. There is no kernel execution gate, protected AV service, behavior-based ransomware prevention, signed installer or independent antivirus certification yet.
