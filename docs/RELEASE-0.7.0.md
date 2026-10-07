# Sentinel v0.7.0 — scan controls and smaller allocations

Pause/resume local scans from the status bar and choose Balanced or Low impact in File scanner. Canceling while paused wakes the worker and retains completed findings. The CLI supports `scan <path> --low-impact`; scan reports record the mode and peak pending directory levels. Historical reports load with balanced defaults.

Streaming folder traversal replaces the wide path queue with at most 64 directory enumerators. Windows enumeration metadata is reused for traversal, with fresh leaf/parent checks before reads. Ordinary prefixes share the read buffer, filename checks use spans, and repeated public threat labels/sources share text within each catalog. Report load/save and CLI JSON stream without whole-output byte/string copies; report size, validation, atomic replacement, archive integrity and remediation gates remain.

A same-harness Mac ARM64 synthetic comparison measured 49.8% fewer report round-trip allocated bytes, 14.3% less retained managed memory after catalog loading, and 7.9% fewer wide-folder allocated bytes. Timing varied; report streaming was slightly slower in the final paired run. These are not Windows working-set or product-wide performance measurements. The repository includes raw outputs, methodology and a repeatable benchmark project.

Local verification: 112 core tests, 13 server tests and real local HTTP/CLI interoperability pass; native WPF compilation has zero warnings/errors. New cases cover pause/resume/current content, cancellation while paused, retained findings, depth/breadth/entry bounds, metadata/symlink behavior, full multi-megabyte hashes, script prefixes, archive signatures, streamed report overflow/cancellation/recovery, historical defaults and exact signed-payload preservation. Harmless fixture hashes are used for filesystem detections; the standard AV marker stays in memory.

GitHub Actions gates tagged previews on both Windows build/test jobs, checks PE architectures, self-contained runtimes, versions, documentation and ZIP integrity, and publishes Windows x64/ARM64, source, server and checksums. Repository text uses consistent LF endings across builders.

This remains an unsigned development preview. Keep Defender real-time protection enabled. Native Windows pause/status-bar/keyboard/high-contrast behavior, OS enforcement and actual performance still require the Windows acceptance checks.
