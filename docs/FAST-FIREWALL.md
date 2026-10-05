# Fast firewall review — v0.5

**Firewall → Refresh local review** captures at most 1,000 TCP records, their owning process identities and three effective Windows Firewall profiles in one fixed PowerShell process. It does not poll in the background, resolve DNS, query IP reputation or check every executable signature. Local C# policy groups records by PID and checks limited evidence. Inspect a selected publisher only when useful.

Review priorities are routine, review and urgent. Disabled firewall profiles are urgent even if the TCP table is empty. Missing/duplicate profiles, unknown policies/identities, incomplete captures, non-loopback listeners and failed signature checks require review. Non-local connections without publisher evidence also warrant inspection. Unsigned software, non-local addresses and listening sockets are not malware verdicts. Routine means no specific issue in the supplied limited checks; it does not prove safety.

Addresses are categorized using literal parsing, without DNS: loopback, private/link-local/shared local ranges, non-local, unspecified or unknown. Non-local is not a guarantee of Internet routability or reputation. A socket bound beyond loopback may remain unreachable because of firewall/routing. TCP snapshots cannot establish inbound/outbound initiation, matching rule attribution or packet content. UDP is not included.

Before selected publisher inspection or an outbound block, Windows rechecks PID, UTC process start time and executable path. A changed/exited/reused process fails visibly. The block confirmation names the exact executable path and its effects; Windows enforces the rule after Sentinel exits. This path rule affects future binaries at that path, requires administrator permission, may be overridden by managed policy and does not close listening sockets. Only user-confirmed actions call OS write methods.

## Optional Jev review

Use Settings → Jev structured decisions to configure TypeSafe or Vercel Gateway. The app requires a snapshot no older than two minutes and an explicit sharing checkbox. The read-only preview contains exactly the serialized state submitted: schema version, counts, availability flags and one fixed signature category. Names, paths, PIDs, raw IPs and publisher/error text are absent. No chat/tool inventory or file contents are sent.

The TypeSafe preset sends `POST https://api.typesafe.ai/v1/systemone` with model `jev-latest`; the Gateway preset sends `POST https://ai-gateway.vercel.sh/typesafe/v1/systemone` with model `typesafe-ai/jev`. Both use Bearer authentication and the documented TypeSafe-compatible contract. A user-configured local fixture is allowed on loopback HTTP; other endpoints require HTTPS without embedded credentials/query/fragment. Transport disables redirects.

One named choice question returns routine/review/urgent. Responses are limited to 64 KiB and 12 JSON nesting levels; duplicate fields, missing/unknown choices, non-finite/out-of-range probabilities, a distribution not summing approximately to one, or a selected choice below the maximum probability are rejected. Reported confidence must be at least 0.80 and selected probability at least 0.85 to retain a routine model priority. These are conservative development thresholds, not calibrated antivirus guarantees. An urgent model result remains urgent even at low confidence. Local warnings always establish a minimum priority.

A five-second deadline covers HTTP and response reading. Failure requires manual review, preserves local evidence, makes no automatic retry and is not cached. Cancellation propagates. The native host allows one review request at a time and rechecks its in-memory cache after waiting. Identical settings, credential identity and sanitized evidence reuse successful results for two minutes. The cache retains at most 128 entries, persists nothing and cannot authorize an action.

## CLI and measurement

`Sentinel.Scanner.exe network-snapshot` reads the live Windows snapshot as JSON. This includes local private paths and addresses; store/share it deliberately. `network-review <absolute snapshot.json>` evaluates a bounded local import offline and identifies historical data. Exit 4 means review is needed, including stale/incomplete snapshots; exit 0 remains no specific issue in limited evidence.

`jev-review <absolute evidence.json> --provider TypeSafe` consumes the selected application's `evidence` object from the local review output. It uses `SENTINEL_JEV_KEY` from the environment. Gateway uses `--provider VercelGateway`; `--endpoint` and `--model` allow explicit test endpoints. The CLI makes one explicit provider request, changes no rules and emits typed advice. It is not an automatic gate for other agents. Do not put credentials into command-line arguments or JSON evidence.

`network-benchmark --iterations 1000` measures only warmed synthetic local policy evaluation over 1,000 TCP records / 250 process identities. It reports median/p95 and allocated bytes. It excludes Windows capture, WPF, startup, file scanning and model latency. Native Windows x64/ARM64 performance, sustained overhead and model classification quality remain unmeasured; run the acceptance matrix before production claims.

References: [Windows TCP snapshot API](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2025-ps), [TypeSafe HTTP schema](https://api.typesafe.ai/docs), [Gateway TypeSafe compatibility](https://vercel.com/i/jev-integrations).
