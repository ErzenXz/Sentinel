using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Sentinel.Core.Protection;
using Forms = System.Windows.Forms;

namespace Sentinel.App;

public partial class MainWindow
{
    private ProtectionPreferences preferences = new();
    private FeedUpdateLoop? feedUpdates;
    private long updaterGeneration;
    private string? monitorFolder;
    private sealed class MonitorMessages
    {
        public FindingInbox Findings { get; } = new();
        public string? Problem;
        public long ShownDropped;
        public MonitorRecoveryStatus? ShownRecovery;
    }
    private MonitorMessages? monitorMessages;
    private Task? stoppingMonitor;
    private readonly DispatcherTimer monitorTimer = new() { Interval = TimeSpan.FromMilliseconds(200) };
    private Forms.NotifyIcon? tray;
    private Forms.ContextMenuStrip? trayMenu;
    private readonly DetectionAlerts alerts = new();
    private readonly DispatcherTimer alertTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private bool exiting, shutdownStarted, sessionStarted;

    private void InitializeSession()
    {
        try { preferences = LocalStore.LoadPreferences(); } catch (Exception ex) { engineError = "Protection preferences could not be loaded: " + ex.Message; }
        SourceInitialized += (_, _) => {
            var source = System.Windows.Interop.HwndSource.FromHwnd(new System.Windows.Interop.WindowInteropHelper(this).Handle);
            source?.AddHook((IntPtr window, int message, IntPtr wParam, IntPtr lParam, ref bool handled) => {
                if (ProfileInstance.ActivationMessage != 0 && (uint)message == ProfileInstance.ActivationMessage) { PostEngine(RestoreWindow); handled = true; }
                return IntPtr.Zero;
            });
        };
        alertTimer.Tick += (_, _) => ShowAlert(alerts.Flush(preferences.NotifyDetections));
        monitorTimer.Tick += (_, _) => FlushMonitorMessages();
        Closing += (_, e) => {
            if (shutdownStarted) return;
            if (!exiting && preferences.KeepInTray && !IsAdmin && tray is not null)
            { e.Cancel = true; Dispatcher.BeginInvoke(() => Hide()); StatusText = "Sentinel is running in the tray."; return; }
            e.Cancel = true; exiting = true; Dispatcher.BeginInvoke(() => _ = ShutdownSession());
        };
    }
    private void BeginSession()
    {
        if (sessionStarted) return; sessionStarted = true;
        try { ConfigureTray(); } catch (Exception ex) { StatusText = "Tray mode is unavailable: " + ex.Message; }
        if (!IsAdmin && preferences.RememberMonitor)
        {
            try { BeginMonitor(preferences.MonitorFolder); }
            catch (Exception ex) { engineError = "Saved monitoring folder could not be resumed: " + ex.Message; StatusText = engineError; }
        }
        StartFeedUpdates();
    }
    private void BeginMonitor(string folder)
    {
        if (monitor is not null || stoppingMonitor is { IsCompleted: false }) throw new InvalidOperationException("Wait for the current monitor to stop before starting another.");
        if (FolderMonitor.IsWithin(folder, LocalStore.Root)) throw new ArgumentException("Choose a folder outside Sentinel's own storage.");
        folder = FileSafety.NormalizeRegularPath(folder);
        var messages = new MonitorMessages();
        monitor = new(folder, () => new FileScanner(feeds.Current, control: new(ScanMode.LowImpact)), messages.Findings.Add,
            problem => Interlocked.Exchange(ref messages.Problem, problem), [LocalStore.Root]);
        monitorMessages = messages; monitorFolder = folder; monitorTimer.Start();
    }
    private void FlushMonitorMessages()
    {
        if (lifetime.IsCancellationRequested || monitorMessages is not { } messages || monitor is not { } active) return;
        ApplyMonitorMessages(messages, active);
    }
    private void ApplyMonitorMessages(MonitorMessages messages, FolderMonitor active)
    {
        var added = 0; var detections = 0;
        foreach (var finding in messages.Findings.Drain())
        {
            var duplicate = engineFindings.FirstOrDefault(x => string.Equals(x.Path, finding.Path, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
                && x.ArchiveEntry == finding.ArchiveEntry && string.Equals(x.Sha256, finding.Sha256, StringComparison.OrdinalIgnoreCase) && x.Verdict == finding.Verdict);
            if (duplicate is not null) continue;
            if (engineFindings.Count >= 2_000)
            {
                var expendable = engineFindings.FirstOrDefault(x => x.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile));
                engineError = "Live findings reached the display limit. Run and save a manual scan for a complete report.";
                Interlocked.Exchange(ref messages.Problem, engineError);
                if (expendable is null || finding.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile)) continue;
                engineFindings.Remove(expendable);
            }
            engineFindings.Add(finding); added++;
            if (finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile) detections++;
        }
        if (detections > 0) NotifyDetection(detections);
        if (added > 0 && !busy) StatusText = $"Folder monitor: {added} new findings to review · {detections} exact detections.";
        var recovery = active.RecoveryStatus;
        if (recovery != messages.ShownRecovery)
        {
            messages.ShownRecovery = recovery;
            if (!busy) StatusText = !active.IsRunning ? "Folder monitoring stopped. Review its coverage and restart monitoring."
                : recovery.Scanning ? "Rechecking the watched folder in Low impact mode…"
                : recovery.Pending ? "Folder recovery queued. Changed files continue to be checked during the cooldown."
                : recovery.LastCompleted is not null ? $"Watched folder rechecked: {recovery.Scanned:N0} files · {recovery.Detected} detections · {(recovery.Incomplete ? "coverage gaps — review monitoring details" : "no scan gaps reported")}."
                : "Folder monitoring is running.";
        }
        var problem = Interlocked.Exchange(ref messages.Problem, null);
        if (messages.Findings.Dropped != messages.ShownDropped)
        {
            messages.ShownDropped = messages.Findings.Dropped;
            problem = $"The monitoring display queue omitted {messages.ShownDropped:N0} findings. Exact detections take priority. Run and save a manual scan for a report.";
        }
        if (problem is not null) { engineError = problem; if (!busy) StatusText = problem; }
    }
    private void StartFeedUpdates()
    {
        if (feedUpdates is not null || !preferences.AutoUpdateFeeds || string.IsNullOrWhiteSpace(protection.PublicKeyPem) || lifetime.IsCancellationRequested) return;
        var settings = protection; var generation = ++updaterGeneration;
        feedUpdates = new(async token => {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromMinutes(2));
            await feeds.UpdateAsync(http, settings, deadline.Token);
        }, state => PostEngine(() => {
            if (lifetime.IsCancellationRequested || generation != updaterGeneration) return;
            if (state.NextAttempt is not null && !state.Failed) monitor?.RequestRecovery();
            if (!busy && state.NextAttempt is not null)
                StatusText = state.Failed ? "Automatic feed check failed. The verified cache remains available; check the server and retry manually." : "Signed feed checked. Next automatic check in six hours.";
        }));
    }
    private async Task StopFeedUpdates()
    {
        updaterGeneration++;
        var active = feedUpdates; feedUpdates = null;
        if (active is not null) await active.DisposeAsync();
    }
    private void ConfigureTray()
    {
        var needed = (preferences.KeepInTray || preferences.NotifyDetections) && !IsAdmin;
        if (needed && tray is null)
        {
            var menu = new Forms.ContextMenuStrip();
            menu.Items.Add("Open Sentinel", null, (_, _) => PostEngine(RestoreWindow));
            menu.Items.Add("Stop folder monitoring", null, (_, _) => PostEngine(() => _ = StopMonitor()));
            menu.Items.Add("Exit Sentinel", null, (_, _) => PostEngine(() => { exiting = true; Close(); }));
            var icon = new Forms.NotifyIcon { Icon = System.Drawing.SystemIcons.Shield, Text = "Sentinel — security preview", ContextMenuStrip = menu, Visible = true };
            icon.DoubleClick += (_, _) => PostEngine(RestoreWindow);
            icon.BalloonTipClicked += (_, _) => PostEngine(() => { RestoreWindow(); ShowPage("Sentinel engine"); });
            trayMenu = menu; tray = icon;
        }
        if (!needed) DisposeTray();
        if (needed && preferences.NotifyDetections) alertTimer.Start(); else alertTimer.Stop();
        if (!preferences.NotifyDetections) _ = alerts.Flush(false);
    }
    private void DisposeTray()
    {
        alertTimer.Stop();
        if (tray is not null) { tray.Visible = false; tray.Dispose(); tray = null; }
        trayMenu?.Dispose(); trayMenu = null;
    }
    private void RestoreWindow() { Show(); if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal; Activate(); }
    private void NotifyDetection(int count) => ShowAlert(alerts.Record(count, preferences.NotifyDetections && !IsAdmin));
    private void ShowAlert(string? message)
    {
        if (message is null || tray is null || lifetime.IsCancellationRequested) return;
        try { tray.ShowBalloonTip(8_000, "Sentinel: detection needs review", message, Forms.ToolTipIcon.Warning); }
        catch (Exception) { StatusText = "A detection needs review. Windows could not show a notification; open File scanner."; }
    }
    private async Task ShutdownSession()
    {
        if (shutdownStarted) return; shutdownStarted = true;
        lifetime.Cancel(); operation?.Cancel(); monitorTimer.Stop(); monitorMessages = null; DisposeTray();
        try { await StopFeedUpdates(); await StopMonitor(); }
        catch (Exception) { /* Shutdown still releases the window and network resources. */ }
        if (operationFinished is { } pending) await pending.Task;
        http.Dispose(); Close();
    }
    private void SessionPreferencesCard()
    {
        var body = Card("Everyday preferences");
        body.Children.Add(Note("Sentinel can stay in the tray after you close its window. It continues this folder monitor and optional signed-feed checks until you choose Exit Sentinel. This installs no Windows service or login startup entry."));
        var keep = new CheckBox { Content = "Keep Sentinel running in the tray when I close the window", IsChecked = preferences.KeepInTray, IsEnabled = !IsAdmin };
        var notifications = new CheckBox { Content = "Notify me about exact detections (counts only)", IsChecked = preferences.NotifyDetections, IsEnabled = !IsAdmin };
        var update = new CheckBox { Content = "Check my trusted server now and every six hours while Sentinel runs", IsChecked = preferences.AutoUpdateFeeds };
        var resume = new CheckBox { Content = "Resume this monitoring folder the next time I open Sentinel", IsChecked = preferences.RememberMonitor, IsEnabled = !IsAdmin };
        foreach (var item in new[] { keep, notifications, update, resume }) body.Children.Add(item);
        var selectedFolder = monitorFolder ?? preferences.MonitorFolder;
        var folderNote = Note(string.IsNullOrEmpty(selectedFolder) ? "Choose and start a folder monitor before enabling resume." : "Resume folder: " + selectedFolder, null); folderNote.Margin = new Thickness(0, 6, 0, 4);
        body.Children.Add(folderNote);
        var state = feedUpdates?.Status;
        body.Children.Add(Note(state is null ? "Automatic feed checking is off, or no signing key is configured." : $"Automatic checking: {(state.Running ? "running" : "stopped")} · last attempt {state.LastAttempt?.ToLocalTime():g} · last success {state.LastSuccess?.ToLocalTime():g} · next {state.NextAttempt?.ToLocalTime():g} · {(state.Failed ? "FAILED; cached intelligence retained" : "no failed check reported")}", state?.Failed == true ? "Warning" : null));
        body.Children.Add(Row(Button("Save protection preferences", () => _ = Run("Save protection preferences", async _ => {
            var next = new ProtectionPreferences(keep.IsChecked == true, notifications.IsChecked == true, update.IsChecked == true, resume.IsChecked == true, selectedFolder);
            ProtectionPreferencesStore.Validate(next);
            if (next.RememberMonitor && FolderMonitor.IsWithin(next.MonitorFolder, LocalStore.Root)) throw new ArgumentException("Sentinel storage cannot be the resumed folder.");
            LocalStore.SavePreferences(next); preferences = next; ConfigureTray();
            await StopFeedUpdates(); StartFeedUpdates();
            if (page is "Sentinel engine" or "Settings") ShowPage(page);
        }), true), Button("Exit Sentinel", () => { exiting = true; Close(); })));
        body.Children.Add(Note("Resume starts a bounded scan of existing files in Low impact mode and is skipped in elevated sessions. Windows notification settings can suppress alerts; local findings stay visible. Exit Sentinel requests cancellation and waits for the active operation to settle. Closing to the tray leaves scans and monitoring running."));
    }
}
