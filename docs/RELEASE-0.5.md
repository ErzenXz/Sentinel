# Sentinel 0.5.0 — fast firewall decisions

Adds a bounded on-demand network review with deterministic local priorities, one Windows capture process, selected-only publisher inspection and fresh PID/start/path checks before proposed app blocking. Optional Jev classification supports TypeSafe directly and Vercel Gateway via a separate DPAPI-encrypted connection. Only explicitly reviewed categories/counts are shared; no paths, IPs or process names enter the model payload.

The small C# review host serializes requests, caches identical successful decisions in memory for two minutes (128 entries), uses a five-second deadline, rejects malformed/contradictory probability responses and retains local warnings. Model replies authorize no changes. New CLI commands support offline network review, explicit Jev review and repeatable local-policy measurement.

Jev and fx were researched from their official schemas/source, including fx's host permission architecture. Sentinel uses its own native host; fx and an additional JavaScript/model runtime are not bundled. All v0.4 usability and prior independent engine/server features remain.

Validation: 94 core tests, 13 server tests, actual local HTTP-to-CLI integration, WPF Release compilation and self-contained Windows x64/ARM64 packages. See VERIFICATION.md for measured synthetic local-policy results and unverified native/live-provider acceptance. No paid model request, new live IOC download or Windows benchmark was performed. This unsigned preview remains complementary to Defender.
