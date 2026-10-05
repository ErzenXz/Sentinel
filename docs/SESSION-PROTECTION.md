# Session protection — v0.4

Open **Settings → Everyday preferences**. Every option starts disabled and is saved to bounded local `protection-preferences.json`:

- Keep in tray: closing the window hides it while active scans and the monitor continue. Open from the tray or reopen the same executable. **Exit Sentinel** cancels and waits for active work, then disposes the monitor, feed worker and network client.
- Detection notifications: native Windows count-only notifications for exact/test detections. Burst alerts are accumulated and limited to one every 30 seconds; the timer flushes pending counts. Windows notification policies can suppress them. Review retained findings in Sentinel.
- Automatic feeds: requires your configured, pinned public key. Check immediately, then six hours after completion, with a two-minute deadline and no overlapping automatic requests. Signature, expiry and sequence checks still apply. Failed checks retain cached intelligence and the prior successful-check time. There is no catch-up burst or automatic key acceptance. Changing trust stops the worker and serializes reset with updates.
- Resume folder: saves the current monitored folder for the next interactive start. This requires an absolute local folder outside Sentinel storage. It does not scan existing files. Missing/unsafe folders fail visibly; elevated sessions skip personal-folder resume and tray features.

There is no Windows service, login auto-start entry, kernel interception or AI background loop. Scheduled scans remain a separate opt-in limited-user Task Scheduler feature. A user-mode watcher observes changes after they occur; keep Defender enabled.

One interactive process is allowed per profile within the Windows session. Reopening the same executable requests window activation. A different executable location may need you to open the existing tray icon and exit it first. Native activation, UAC handoff, shutdown/power-loss and notification behavior still need Windows acceptance testing.

Search/verdict filters on the findings grid and status filters on scan history only change the view. They never discard evidence or alter report totals.

Native references: [NotifyIcon](https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.notifyicon?view=windowsdesktop-10.0), [WPF high contrast](https://learn.microsoft.com/en-us/dotnet/api/system.windows.systemparameters.highcontrast?view=windowsdesktop-10.0), [registered window messages](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerwindowmessagew).
