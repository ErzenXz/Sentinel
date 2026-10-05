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
        if (monitor is not null) throw new InvalidOperationException("Stop the current monitor before starting another.");
        if (FolderMonitor.IsWithin(folder, LocalStore.Root)) throw new ArgumentException("Choose a folder outside Sentinel's own storage.");
        folder = FileSafety.NormalizeRegularPath(folder);
        var generation = ++monitorGeneration;
        monitor = new(folder, Scanner, finding => PostEngine(() => {
            if (lifetime.IsCancellationRequested || generation != monitorGeneration) return;
            var duplicate = engineFindings.FirstOrDefault(x => x.Path == finding.Path && x.ArchiveEntry == finding.ArchiveEntry && x.Sha256 == finding.Sha256 && x.Verdict == finding.Verdict);
            if (duplicate is not null) return;
            if (engineFindings.Count >= 2_000)
            {
                var expendable = engineFindings.FirstOrDefault(x => x.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile));
                engineFindings.Remove(expendable ?? engineFindings[0]);
                engineError = "Live findings reached the display limit. Run and save a manual scan for a complete report.";
            }
            engineFindings.Add(finding); StatusText = $"Folder monitor: {finding.Verdict}. Open Sentinel engine to review.";
            if (finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile) NotifyDetection(1);
        }), problem => PostEngine(() => {
            if (!lifetime.IsCancellationRequested && generation == monitorGeneration) { engineError = problem; StatusText = problem; }
        }), [LocalStore.Root]);
        monitorFolder = folder;
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
        lifetime.Cancel(); operation?.Cancel(); DisposeTray();
        try { await StopFeedUpdates(); if (monitor is not null) { var active = monitor; monitor = null; await active.DisposeAsync(); } }
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
        body.Children.Add(Note("Resume does not scan existing files and is skipped in elevated sessions. Windows notification settings can suppress alerts; local findings stay visible. Exit Sentinel requests cancellation and waits for the active operation to settle. Closing to the tray leaves scans and monitoring running."));
    }
}
