# Native UI — v0.8.0

Sentinel uses WPF, Segoe UI and Segoe MDL2 Assets. The redesign uses a charcoal navigation rail, a warm light canvas and dark-green primary actions. Sections use thin separators, with one scan entry panel on Home. No new dependencies, image assets, web view, animation loop or model runtime are shipped.

Home starts with file/folder scanning. Compact rows show timestamped Windows checks, folder monitoring and threat-list freshness. A saved scan is summarized in one line with its incomplete/canceled/stale qualification. A healthy Windows reading describes only the observed Defender/firewall state; it does not declare every file safe. Unavailable readings and stale/demo lists remain explicit.

File scanner, Firewall and Applications use a table and a selectable evidence inspector. The inspector is 320 pixels wide beside the table when the content area reaches 820 pixels, including a 20-pixel gap; below that it stacks. Verdict columns have minimum widths so text labels fit. Scanner timing is below the results. Exact threat, test detection, review, no known match, skipped and error remain distinct; a no-match result is never called safe. Empty data and read failures remain distinct. Actions retain selected-row, freshness, identity and standard-user eligibility.

Monitoring, scheduling, raw TCP/rules, scanner limits and optional Jev use expandable rows. Settings groups everyday preferences, server trust and optional model connections. Direct links expand, scroll to and focus their section; expansion is remembered for the session.

AI is optional. The advisor sends a snapshot only after its sharing checkbox is selected. Jev shows the exact categories/counts payload and resets consent on selection changes. Model output cannot directly change protection settings.

| Keys | Action |
|---|---|
| Ctrl+O | Choose a file for a Sentinel scan |
| Ctrl+Shift+O | Choose a folder for a Sentinel scan |
| F6 / Shift+F6 | Switch between navigation and page content |
| Up / Down / Home / End on navigation | Move focus; Enter/Space opens the page |
| Escape while busy | Request cancellation; Windows operations may continue |
| Tab / Shift+Tab | Move between enabled controls |

The window remains 1200 × 820 by default, minimum 960 × 680, with wrapping and scrolling. The rail is 212 pixels wide; body insets are 36/20/28/24. Titles are 26 pixels, section headings 16, body 13 and notes 12. Buttons/inputs are at least 34 pixels high; grid rows are 38 and headers 34. Home review rows are at least 48 including padding, growing for wrapped content. Focus rings use separate page/rail resources; the selected rail item uses HighlightText on Highlight in high contrast.

Busy operations disable page controls while navigation, scrolling and Stop waiting remain reachable. Local scans expose Pause scan / Resume scan and Cancel scan in the status bar; pause requests apply at the next checkpoint and stop the indeterminate animation. Cancellation stays reachable while paused. Other operations keep Stop waiting. File scanner provides a session-only Balanced / Low impact selector. Worker scan updates replace one pending record, sampled every 200 ms with a final flush. Live-region messages retain coalesced 1.5-second notification, including repeated validation feedback.

| Token | Normal color |
|---|---|
| Canvas / panel / input | `#F7F6F2` / `#F0EEE8` / `#FFFFFF` |
| Main / muted text | `#1C1F1D` / `#595E58` |
| Primary / primary text | `#1F5C45` / `#FFFFFF` |
| Selected surface / text | `#E2ECE5` / `#143A2C` |
| Positive / attention / destructive text | `#1E6B4D` / `#8A5A12` / `#A3271B` |
| Input outline | `#8C887F` |
| Rail / rail text / rail muted | `#1E2320` / `#D5D9D4` / `#9AA19B` |
| Selected rail / text / indicator | `#343B36` / `#FFFFFF` / `#7CC4A0` |

The 42 initial brush values match Theme.Apply. High contrast substitutes system brushes. Selected numeric text checks meet 4.5:1; field and focus-outline checks meet 3:1. These source checks do not certify native rendering or full accessibility.

Claude Code was explicitly invoked with `claude -p --model claude-opus-5-5 --effort medium`. It implemented the shell, shared styles, page layouts and initial three-page mockup. Its source changes were reviewed and built; final adjustments address column widths, inspector geometry, selected rail focus, Home density, timing placement, preview hidden states, stale-feed information and the actual Jev payload schema. No credentials, user files or live security snapshots were supplied for this design work.

The Mac images are browser-rendered source-based mockups with example data, not Windows screenshots. They share native colors, desktop labels and geometry, with Arial/Lucide fallbacks; the preview adds narrower layouts below the native window minimum. Windows fonts, DPI, Narrator, high-contrast behavior, glyph appearance, dropdowns, sorting/clipboard and layout near the inspector breakpoint still require [Windows acceptance checks](WINDOWS-ACCEPTANCE.md).

Glyph identifiers were checked against [Microsoft's Segoe MDL2 reference](https://learn.microsoft.com/en-us/windows/apps/design/iconography/segoe-ui-symbol-font); native appearance remains a Windows acceptance check.

## Monitoring updates in v0.8

Folder monitoring explains initial coverage, Low impact mode, the five-minute recovery budget and incomplete results. A Recheck watched folder action shares the same worker and cooldown as automatic recovery. Status counts update once a second while the monitoring section is loaded; the timer stops when the page unloads. Worker findings enter a 512-item deduplicated inbox and the session timer drains at most 128 every 200 ms. Notifications are count-only and batch detections; monitor callbacks no longer enqueue UI closures per finding or per problem.
