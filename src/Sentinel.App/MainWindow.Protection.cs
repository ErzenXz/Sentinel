using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Microsoft.Win32;
using Sentinel.Core.Protection;

namespace Sentinel.App;

public partial class MainWindow
{
    private readonly FeedRepository feeds = new(Path.Combine(LocalStore.Root, "engine"));
    private readonly QuarantineVault vault = new(Path.Combine(LocalStore.Root, "quarantine"), new WindowsVaultKeyProtector());
    private readonly ObservableCollection<FileFinding> engineFindings = [];
    private ProtectionSettings protection = new();
    private FolderMonitor? monitor;
    private ScheduleStatus? scheduleStatus;
    private static string ReportsDirectory => Path.Combine(LocalStore.Root, "reports");
    private string? engineError;
    private ScanReport? lastScan;
    private FileFinding? advisorFinding;
    private string findingsSearch = "";
    private FindingScope findingsScope;
    private ScanMode scanMode;
    private ScanControl? manualScan;
    private string AdvisorSnapshot() => System.Text.Json.JsonSerializer.Serialize(new {
        windows = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(Sentinel.Core.AiClient.SnapshotForAi(snapshot)),
        sentinel = new { feedSequence = feeds.Current?.Payload.Sequence, hashes = (feeds.Current ?? BuiltInCatalog.Current).Hashes.Count,
            feedStale = (feeds.Current ?? BuiltInCatalog.Current).IsExpired(DateTimeOffset.UtcNow), monitored = monitor?.IsRunning ?? false,
            missedEvents = monitor?.DroppedEvents ?? 0, pendingDetections = engineFindings.Count(x => x.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile), lastScan = lastScan is null ? null : new { lastScan.Scanned, lastScan.Detected, lastScan.Review, lastScan.Skipped, lastScan.Errors, lastScan.LimitReached, lastScan.FindingsTruncated, lastScan.Canceled, lastScan.ArchiveEntries } },
        selectedFinding = advisorFinding is null ? null : new { verdict = advisorFinding.Verdict.ToString(), reason = advisorFinding.Verdict is FileVerdict.Error or FileVerdict.Skipped ? "This item was not fully scanned; review the local error details." : advisorFinding.Reason, extension = Path.GetExtension(advisorFinding.ArchiveEntry ?? advisorFinding.Path).Length <= 12 ? Path.GetExtension(advisorFinding.ArchiveEntry ?? advisorFinding.Path) : "other" }
    });
    private void InitializeProtection()
    {
        try { protection = LocalStore.LoadProtection(); if (!string.IsNullOrWhiteSpace(protection.PublicKeyPem)) feeds.Load(protection.PublicKeyPem); }
        catch (Exception ex) { engineError = ex.Message; }
        try
        {
            lastScan = ScanReports.Latest(ReportsDirectory);
            if (lastScan is not null) foreach (var finding in lastScan.Findings) engineFindings.Add(finding);
        }
        catch (Exception ex) { engineError = "Saved scan report could not be loaded: " + ex.Message; }
    }
    private FileScanner Scanner() => new(feeds.Current);
    private string FeedDescription()
    {
        var feed = feeds.Current;
        if (feed is null) { var bundled = BuiltInCatalog.Current; return $"Bundled ESET public IOC snapshot · {bundled.Hashes.Count:N0} hashes · {(bundled.IsExpired(DateTimeOffset.UtcNow) ? "STALE — connect a server for updates" : "published " + bundled.Payload.IssuedAt.ToLocalTime().ToString("d"))} · no server connected"; }
        var demoOnly = feed.Payload.Hashes.Count == 0 || feed.Payload.Hashes.All(x => x.Source.StartsWith("Sentinel demo", StringComparison.Ordinal));
        return $"{feed.Hashes.Count:N0} hashes · sequence {feed.Payload.Sequence} · {(demoOnly ? "demonstration list only" : "operator-supplied intelligence")} · {(feed.IsExpired(DateTimeOffset.UtcNow) ? "STALE — update needed" : "expires " + feed.Payload.ExpiresAt.ToLocalTime().ToString("g"))}";
    }
    private bool FeedNeedsAttention => (feeds.Current ?? BuiltInCatalog.Current).IsExpired(DateTimeOffset.UtcNow) || feeds.Current is { } feed && (feed.Payload.Hashes.Count == 0 || feed.Payload.Hashes.All(x => x.Source.StartsWith("Sentinel demo", StringComparison.Ordinal)));
    private string FeedStatusNote()
    {
        if (feeds.Current is { } feed && (feed.Payload.Hashes.Count == 0 || feed.Payload.Hashes.All(x => x.Source.StartsWith("Sentinel demo", StringComparison.Ordinal))))
            return "The server supplies a demonstration list. Add threat intelligence before relying on it.";
        if ((feeds.Current ?? BuiltInCatalog.Current).IsExpired(DateTimeOffset.UtcNow))
            return "Threat list is out of date. It still matches old known hashes; connect or update a trusted server in Settings.";
        return feeds.Current is null ? "Using bundled public indicators. Connect a trusted server in Settings for updates." : "A verified local threat list is available. Unknown or changed files can have no match.";
    }
    // Feed state as a chip: stale or demonstration lists are called out; a current list is not called "safe".
    private Border FeedChip() => FeedNeedsAttention
        ? Chip((feeds.Current ?? BuiltInCatalog.Current).IsExpired(DateTimeOffset.UtcNow) ? "Threat list stale" : "Demonstration list", Tone.Warning)
        : Chip(feeds.Current is null ? "Bundled list" : "Verified list", Tone.Neutral);
    private void EnginePage()
    {
        var top = Card();
        var toolbar = new Grid();
        toolbar.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) }); toolbar.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        var actions = Row(IconButton("", "Scan a file…", ChooseScanFile, true), IconButton("", "Scan a folder…", ChooseScanFolder), QuietButton("Scan history", () => ShowPage("Scan reports")));
        actions.Margin = new Thickness(0);
        var feedChip = FeedChip(); feedChip.VerticalAlignment = VerticalAlignment.Top; feedChip.Margin = new Thickness(16, 8, 0, 0); Grid.SetColumn(feedChip, 1);
        toolbar.Children.Add(actions); toolbar.Children.Add(feedChip); top.Children.Add(toolbar);
        top.Children.Add(Note("Checks files against known threat hashes on this PC. ZIP contents are checked within limits. New or changed threats can have no match."));
        top.Children.Add(Note(FeedStatusNote(), FeedNeedsAttention ? "Warning" : "Muted"));
        var speed = new ComboBox { ItemsSource = new[] { "Balanced", "Low impact" }, SelectedIndex = (int)scanMode, Width = 155 };
        Named(speed, "Speed for the next Sentinel scan");
        speed.SelectionChanged += (_, _) => { if (speed.SelectedIndex >= 0) scanMode = (ScanMode)speed.SelectedIndex; };
        top.Children.Add(Row(Field("Scan speed", speed)));
        top.Children.Add(Note("Low impact adds brief pauses between read chunks and small files. Both modes use the same detection rules and limits. You can pause, resume or cancel a running local scan from the status bar."));
        if (engineError is not null) top.Children.Add(Note(engineError, "Warning"));
        if (lastScan is { } report)
        {
            var summary = Card(compact: true);
            summary.Children.Add(SectionHeader("Last saved scan", Note(report.StartedAt.ToLocalTime().ToString("g"))));
            summary.Children.Add(ReportStats(report));
            summary.Children.Add(Note(ScanCoverage(report), report.Canceled || report.LimitReached || report.FindingsTruncated || report.Skipped + report.Errors > 0 ? "Warning" : "Muted"));
        }
        var body = Card();
        var table = Table(("File / archive entry", "DisplayPath", 3), ("Result", "Verdict", 1), ("Evidence", "Reason", 4));
        var view = new ListCollectionView(engineFindings);
        var search = new TextBox { Text = findingsSearch, MaxLength = 256, Width = 280 };
        var scope = new ComboBox { ItemsSource = Enum.GetValues<FindingScope>(), SelectedItem = findingsScope, Width = 160 };
        System.Windows.Automation.AutomationProperties.SetName(search, "Search findings by path, evidence, or SHA-256");
        System.Windows.Automation.AutomationProperties.SetName(scope, "Filter finding results");
        void ApplyFilter() { findingsSearch = search.Text; findingsScope = (FindingScope)scope.SelectedItem; table.SelectedItem = null; view.Filter = item => FindingSearch.Matches((FileFinding)item,findingsSearch,findingsScope); view.Refresh(); }
        search.TextChanged += (_, _) => ApplyFilter(); scope.SelectionChanged += (_, _) => ApplyFilter();
        var shown = Note(""); shown.SetBinding(TextBlock.TextProperty,new Binding("Count") { Source=view, StringFormat="Showing {0} retained findings" });
        // ListCollectionView directly subscribes to our window-lifetime collection.
        // A discarded page must release that subscription and its filter closure.
        releasePage = () => {
            table.ItemsSource = null;
            BindingOperations.ClearBinding(shown, TextBlock.TextProperty);
            view.Filter = null;
            view.DetachFromSourceCollection();
        };
        body.Children.Add(SectionHeader("Results", shown));
        body.Children.Add(Row(Field("Find a result", search), Field("Show", scope))); ApplyFilter(); table.ItemsSource = view;
        var main = new StackPanel();
        EmptyTable(main, table, "No findings to show. Scan a file or folder, or change the result filter.");
        var hint = Note("Select a finding to see its full path, evidence and SHA-256.");
        var evidence = Readout("Selected finding evidence", 180); evidence.Visibility = Visibility.Collapsed;
        table.SelectionChanged += (_, _) => {
            evidence.Visibility = table.SelectedItem is FileFinding ? Visibility.Visible : Visibility.Collapsed;
            hint.Visibility = table.SelectedItem is FileFinding ? Visibility.Collapsed : Visibility.Visible;
            evidence.Text = table.SelectedItem is FileFinding finding ? finding.DisplayPath + "\n" + finding.Reason + (finding.Sha256 is { } hash ? "\nSHA-256: " + hash : "") : "";
        };
        body.Children.Add(Split(main, Inspector("Selected finding", hint, evidence, Row(WhenSelected(DangerButton("Quarantine selected…", () => { if (table.SelectedItem is FileFinding finding) QuarantineFinding(finding); else StatusText = "Choose a known threat or test-file detection first."; }), table, item => !IsAdmin && item is FileFinding { Verdict: FileVerdict.KnownThreat or FileVerdict.TestFile }), WhenSelected(Button("Explain with AI", () => { if (table.SelectedItem is FileFinding finding) { advisorFinding = finding; ShowPage("AI advisor"); } else StatusText = "Select a finding to explain."; }), table), WhenSelected(Button("Copy SHA-256", () => {
            if (table.SelectedItem is not FileFinding { Sha256: { } hash }) return;
            try { System.Windows.Clipboard.SetText(hash); StatusText = "SHA-256 copied."; } catch (Exception ex) { StatusText = ex.Message; }
        }), table, item => item is FileFinding { Sha256.Length: 64 })))));
        if (lastScan is { } timing)
            Details(body, "Scan timing & coverage", Note($"{timing.StartedAt.ToLocalTime():g} · {timing.Duration.TotalSeconds:F1}s · {(timing.Mode == ScanMode.LowImpact ? "Low impact" : "Balanced")} · {timing.ArchiveEntries:N0} archive entries · {timing.BytesRead / 1024 / 1024:N0} MB read · {timing.ArchiveBytesRead / 1024 / 1024:N0} MB expanded · {timing.PeakPendingDirectories} pending directory levels", null));
        var limits = AdvancedCard("Threat list & scanner limits");
        limits.Children.Add(Text(FeedDescription(), 12, true));
        limits.Children.Add(Note("Checks SHA-256 locally; no AI request is made. Limits: 256 MB per file, 50,000 filesystem entries, 2,000 displayed findings. ZIP: 2,048 entries per tree, 32 MB per entry, 128 MB expanded, 200:1 ratio, two nested levels. Unreadable, skipped and over-budget items remain incomplete. Review patterns are not known malware."));
        var watch = AdvancedCard(monitor?.IsRunning == true ? "Folder monitoring · running" : "Folder monitoring · off");
        watch.Children.Add(Text("Checks existing files when you start, then new and changed files after writes settle. Folder moves and missed changes queue a recovery scan with a five-minute budget. Uses Low impact mode and excludes Sentinel storage. Gaps and limits stay visible. Monitoring stops when you exit; it cannot block execution before a scan. Nothing is removed automatically.", 13));
        var monitorStatus = Text(MonitorDescription(), 12, true);
        watch.Children.Add(monitorStatus);
        var statusTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        statusTimer.Tick += (_, _) => monitorStatus.Text = MonitorDescription();
        monitorStatus.Loaded += (_, _) => statusTimer.Start(); monitorStatus.Unloaded += (_, _) => statusTimer.Stop();
        releasePage += () => statusTimer.Stop();
        watch.Children.Add(Row(Button("Choose folder & start…", () => {
            if (monitor is not null) { StatusText = "Stop the current monitor before starting another."; return; }
            var dialog = new OpenFolderDialog(); if (dialog.ShowDialog() != true) return;
            try { BeginMonitor(dialog.FolderName); ShowPage("Sentinel engine"); StatusText = "Folder monitoring started. Use Exit Sentinel to stop it in tray mode."; }
            catch (Exception ex) { StatusText = ex.Message; }
        }), Button("Recheck watched folder", () => {
            if (monitor?.RequestRecovery() != true) { StatusText = "Start folder monitoring first."; return; }
            StatusText = "Recovery requested. Rechecks share one worker and wait at least 30 seconds between scans.";
        }), Button("Stop monitoring", () => _ = StopMonitor())));
        var schedule = AdvancedCard("Schedule a daily folder scan");
        schedule.Children.Add(Text(scheduleStatus is null ? "Schedule status has not been checked." : !scheduleStatus.Exists ? "No daily scan is registered for this user." : $"{scheduleStatus.State} · next {scheduleStatus.NextRun} · last {scheduleStatus.LastRun} · result {scheduleStatus.LastResult}", 12, true));
        schedule.Children.Add(Button("Check schedule status", () => _ = Run("Read daily scan status", async token => {
            scheduleStatus = await new ScanScheduler(new Sentinel.Core.PowerShellRunner()).StatusAsync(token);
            if (page == "Sentinel engine") ShowPage(page);
        }, audit: false)));
        schedule.Children.Add(Text("Windows Task Scheduler can run our independent scanner while this user is logged in. It reads the cached feed, saves a local report, runs with low CPU priority, and never quarantines automatically. Keep this portable folder in place."));
        schedule.Children.Add(Note("Scanner results: 0 no known match; 1 command failure; 2 detections; 3 incomplete/canceled; 4 review findings. Windows can also return its own Task Scheduler codes."));
        var dailyTime = new TextBox { Text = "18:00", Width = 90, HorizontalAlignment = HorizontalAlignment.Left };
        Named(dailyTime, "Daily scan time, 24-hour HH:mm");
        schedule.Children.Add(FieldLabel("Daily local time (24-hour HH:mm)")); schedule.Children.Add(dailyTime);
        schedule.Children.Add(Row(Button("Choose folder & schedule…", () => {
            if (IsAdmin) { StatusText = "Create the scan schedule from a standard user session."; return; }
            if (!TimeOnly.TryParseExact(dailyTime.Text,"HH:mm",System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.None,out var time)) { StatusText = "Enter a time such as 18:00."; return; }
            var dialog = new OpenFolderDialog(); if (dialog.ShowDialog() != true) return;
            if (MessageBox.Show(this,"Schedule a daily Sentinel scan at " + time.ToString("HH:mm") + " for:\n\n" + dialog.FolderName + "\n\nIt runs when this user is logged in. Windows may defer it on battery power. Results are saved locally; files are not removed.","Schedule scan",MessageBoxButton.YesNo)!=MessageBoxResult.Yes) return;
            var executable=Path.Combine(AppContext.BaseDirectory,"Sentinel.Scanner.exe");
            _ = Run("Schedule daily Sentinel scan",token=>new ScanScheduler(new Sentinel.Core.PowerShellRunner()).RegisterAsync(executable,dialog.FolderName,LocalStore.Root,time.Hour,time.Minute,token));
        }), Button("Remove daily schedule…", () => {
            if (MessageBox.Show(this,"Remove this user's Sentinel daily scan task?","Remove schedule",MessageBoxButton.YesNo)==MessageBoxResult.Yes) _ = Run("Remove daily scan schedule",token=>new ScanScheduler(new Sentinel.Core.PowerShellRunner()).RemoveAsync(token));
        })));
        schedule.Children.Add(Button("Load latest scheduled report", () => {
            try {
                var path=Path.Combine(LocalStore.Root,"reports","scheduled-scan.json");
                if(!File.Exists(path)){StatusText="No scheduled report has been saved yet.";return;}
                LoadScanReport(path);
                ShowPage("Sentinel engine");StatusText="Loaded local scheduled report. Detection is rechecked before quarantine.";
            } catch(Exception ex){StatusText=ex.Message;}
        }));
    }
    private void ThreatServerCard()
    {
        var feed = AdvancedCard("Threat list & trusted server");
        var current = FeedChip(); current.Margin = new Thickness(0, 0, 0, 8); feed.Children.Add(current);
        feed.Children.Add(Text(FeedDescription(), 12, true));
        feed.Children.Add(Text("Self-host the included Node.js server, initialize its signing key, then copy only its public.pem to this PC. Verify the key fingerprint with the operator. Server keys and the MalwareBazaar key stay on the server."));
        feed.Children.Add(FieldLabel("Server base URL")); var endpoint = new TextBox { Text = protection.Endpoint }; feed.Children.Add(endpoint);
        feed.Children.Add(FieldLabel("Pinned RSA public key")); var pem = new TextBox { Text = protection.PublicKeyPem, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 105, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 12 }; feed.Children.Add(pem);
        System.Windows.Automation.AutomationProperties.SetName(endpoint, "Threat server endpoint"); System.Windows.Automation.AutomationProperties.SetName(pem, "Pinned threat server public key");
        feed.Children.Add(Row(Button("Import public.pem…", () => {
            var dialog = new OpenFileDialog { Filter = "Public key|*.pem|All files|*.*" }; if (dialog.ShowDialog() != true) return;
            try { if (new FileInfo(dialog.FileName).Length > 16 * 1024) throw new InvalidDataException("Public key file is too large."); var text = File.ReadAllText(dialog.FileName); _ = FeedVerifier.Fingerprint(text); pem.Text = text; } catch (Exception ex) { StatusText = ex.Message; }
        }), Button("Save server & trust…", () => {
            if (busy || monitor is not null) { StatusText = "Finish the active operation and stop monitoring before changing feed trust."; return; }
            try {
                var next = new ProtectionSettings(endpoint.Text.Trim(), pem.Text.Trim()); _ = Sentinel.Core.AiClient.ValidateEndpoint(next.Endpoint); var fingerprint = FeedVerifier.Fingerprint(next.PublicKeyPem);
                var previousFingerprint = ""; try { if (!string.IsNullOrWhiteSpace(protection.PublicKeyPem)) previousFingerprint = FeedVerifier.Fingerprint(protection.PublicKeyPem); } catch (System.Security.Cryptography.CryptographicException) { }
                var changed = fingerprint != previousFingerprint;
                if (changed && MessageBox.Show(this, "Trust this server's signing key?\n\nSHA-256 fingerprint:\n" + fingerprint + "\n\nCompare it with the server operator. A trusted operator controls the known-threat list. Changing keys resets previous feed rollback protection.", "Trust threat server", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                _ = Run("Save server and trust", async token => {
                    await StopFeedUpdates();
                    if (changed) await feeds.ResetTrustAsync(token);
                    LocalStore.SaveProtection(next); protection = next; engineError = null;
                    StartFeedUpdates();
                });
            } catch (Exception ex) { StatusText = ex.Message; }
        }), Button("Update signed feed", () => _ = Run("Update Sentinel threat feed", async token => {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromMinutes(2));
            await feeds.UpdateAsync(http, protection, deadline.Token); engineError = null; monitor?.RequestRecovery(); if (page is "Sentinel engine" or "Overview" or "Settings") ShowPage(page);
        }, audit: true))));
        feed.Children.Add(Note("Updates reject wrong signatures, expired lists, rollback, and changed content under an existing sequence. A failed update retains the last verified list. An expired cache still matches previously known hashes and is clearly marked stale."));
    }
    private void PostEngine(Action action)
    {
        if (lifetime.IsCancellationRequested || Dispatcher.HasShutdownStarted) return;
        try { Dispatcher.BeginInvoke(action); } catch (InvalidOperationException) { }
    }
    private string MonitorDescription()
    {
        if (monitor?.IsRunning != true) return "Monitoring is off.";
        var state = monitor.RecoveryStatus;
        var recoveryText = state.Scanning ? "Rechecking folder…" : state.Pending ? "Recovery queued" : state.LastCompleted is null ? "Initial scan queued" : $"Last recheck {state.LastCompleted.Value.ToLocalTime():t}: {state.Scanned:N0} files, {state.Detected} detections, {state.Skipped + state.Errors} incomplete";
        if (state.LimitReached || state.FindingsTruncated) recoveryText += "; scan/display limit reached";
        if (state.Canceled) recoveryText += "; time budget reached — run a manual scan";
        var omitted = (monitorMessages?.Findings.Dropped ?? 0) + (monitorMessages?.DisplayOmitted ?? 0);
        return $"Changed files checked: {monitor.CompletedScans:N0} · queued: {monitor.PendingFiles} · missed events: {monitor.DroppedEvents:N0} · omitted display findings: {omitted:N0}\n{recoveryText}";
    }
    private Task StopMonitor()
    {
        if (stoppingMonitor is { IsCompleted: false }) return stoppingMonitor;
        if (monitor is null) return Task.CompletedTask;
        var active = monitor; var messages = monitorMessages; monitor = null; monitorFolder = null; monitorTimer.Stop(); monitorMessages = null;
        if (!lifetime.IsCancellationRequested) StatusText = "Stopping folder monitoring…";
        return stoppingMonitor = FinishStoppingMonitor(active, messages);
    }
    private async Task FinishStoppingMonitor(FolderMonitor active, MonitorMessages? messages)
    {
        try { await active.DisposeAsync(); }
        catch (Exception)
        {
            monitor = active;
            engineError = "Folder monitoring did not stop cleanly. Exit and restart Sentinel before monitoring again.";
            if (!lifetime.IsCancellationRequested) StatusText = engineError;
            return;
        }
        if (lifetime.IsCancellationRequested) return;
        if (messages is not null)
        {
            do { ApplyMonitorMessages(messages, active); } while (messages.Findings.Count > 0);
        }
        if (page == "Sentinel engine") ShowPage(page); StatusText = "Folder monitoring stopped. Retained findings remain available for review.";
    }
    private void StartEngineScan(string path) => _ = Run("Sentinel local scan", async token => {
        var control = new ScanControl(scanMode); manualScan = control;
        PauseScan.Content = "Pause scan"; PauseScan.Visibility = Visibility.Visible; StopOperation.Content = "Cancel scan";
        try
        {
            engineFindings.Clear();
            using var progress = new LatestScanProgress(Dispatcher, p => { if (!lifetime.IsCancellationRequested) StatusText = (control.IsPaused ? "Pause requested · " : "Sentinel scan: ") + $"{p.Scanned:N0} checked · {p.Detected} detections · {p.Review} review · {p.Skipped + p.Errors} incomplete"; });
            var report = await Task.Run(() => new FileScanner(feeds.Current, control: control).ScanPathAsync(path, progress, token));
            manualScan = null; PauseScan.Visibility = Visibility.Collapsed;
            lastScan = report; engineFindings.Clear(); foreach (var item in report.Findings) engineFindings.Add(item);
            await ScanReports.SaveHistoryAsync(report, ReportsDirectory);
            NotifyDetection(report.Detected);
            if (page is "Sentinel engine" or "Overview") ShowPage(page);
        }
        finally { manualScan = null; PauseScan.Visibility = Visibility.Collapsed; StopOperation.Content = "Stop waiting"; }
    }, completedMessage: () => lastScan?.Canceled == true ? "Scan canceled; completed findings saved in Scan history." : lastScan?.Incomplete == true ? "Scan finished with incomplete items; results saved in Scan history." : lastScan?.Detected > 0 ? "Scan finished; detections need review in File scanner." : "Scan finished; results saved in Scan history.");
    private void ToggleScanPause()
    {
        if (manualScan is not { } control) return;
        if (control.IsPaused) { control.Resume(); PauseScan.Content = "Pause scan"; BusyProgress.IsIndeterminate = true; StatusText = "Sentinel scan resumed."; }
        else { control.Pause(); PauseScan.Content = "Resume scan"; BusyProgress.IsIndeterminate = false; StatusText = "Pause requested. Reading stops at the next checkpoint; resume or cancel from here."; }
    }
    private void QuarantineFinding(FileFinding finding)
    {
        if (finding.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile)) { StatusText = "Only exact known-threat or test-file detections can be quarantined. Review patterns cannot remove files."; return; }
        if (IsAdmin) { StatusText = "Restart Sentinel as a standard user before quarantining personal files."; return; }
        if (MessageBox.Show(this, (finding.ArchiveEntry is null ? "Encrypt a recoverable quarantine backup and remove this exact file?\n\n" : "Quarantine the WHOLE archive, including every file inside it? A contained exact detection was found.\n\n") + finding.DisplayPath + "\n\n" + finding.Reason + "\n\nSentinel will recheck its hash. If it changed, the original stays in place.", "Quarantine detected file", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _ = Run("Quarantine detected file", async token => {
            var confirmed = await Scanner().ConfirmQuarantineAsync(finding, token);
            await vault.QuarantineAsync(confirmed, token);
            foreach (var item in engineFindings.Where(x => x.Path == finding.Path).ToArray()) engineFindings.Remove(item);
        });
    }
    private void LoadScanReport(string path)
    {
        var report = ScanReports.Load(path); lastScan = report; engineFindings.Clear();
        foreach (var finding in report.Findings) engineFindings.Add(finding);
    }
    private void ReportsPage()
    {
        var body = Card("Saved Sentinel scans");
        body.Children.Add(Note("The last 30 manual and scheduled reports stay on this PC. Canceled scans retain completed findings. Exported reports include local file paths; review them before sharing. Imported detections are rechecked before quarantine."));
        var reportScope = new ComboBox { ItemsSource = new[] { "All reports", "With detections", "Incomplete reports" }, SelectedIndex = 0, Width = 190 };
        Named(reportScope, "Scan history filter");
        body.Children.Add(Row(Field("Show", reportScope)));
        var table = Table(("Started", "StartedAt", 2), ("Files", "Scanned", 1), ("Detected", "Detected", 1), ("Review", "Review", 1), ("Incomplete", "Incomplete", 1));
        var emptyMessage = "No scans match this view. Run a Sentinel scan or import a saved report.";
        try {
            var all = ScanReports.List(ReportsDirectory);
            void FilterReports() { table.SelectedItem = null; table.ItemsSource = all.Where(x => reportScope.SelectedIndex == 0 || reportScope.SelectedIndex == 1 && x.Detected > 0 || reportScope.SelectedIndex == 2 && x.Incomplete).ToArray(); }
            reportScope.SelectionChanged += (_, _) => FilterReports(); FilterReports();
        } catch (Exception ex) { emptyMessage = "Saved scans could not be read. Review the error above."; body.Children.Add(Note(ex.Message, "Warning")); }
        EmptyTable(body, table, emptyMessage);
        body.Children.Add(Row(WhenSelected(Button("Open selected", () => {
            if (table.SelectedItem is not ReportSummary report) { StatusText = "Select a saved report."; return; }
            try { LoadScanReport(report.Path); ShowPage("Sentinel engine"); } catch (Exception ex) { StatusText = ex.Message; }
        }), table), Button("Import report…", () => {
            var dialog = new OpenFileDialog { Filter = "Sentinel report|*.json" }; if (dialog.ShowDialog() != true) return;
            try { LoadScanReport(dialog.FileName); ShowPage("Sentinel engine"); } catch (Exception ex) { StatusText = ex.Message; }
        }), QuietButton("Refresh", () => ShowPage("Scan reports"))));
        var export = Button("Export current results…", () => {
            if (lastScan is null) { StatusText = "Scan or open a report first."; return; }
            var report = lastScan;
            var dialog = new SaveFileDialog { Filter = "Sentinel report|*.json", FileName = "sentinel-scan.json" };
            if (dialog.ShowDialog() == true) _ = Run("Export scan report", token => ScanReports.SaveAsync(report, dialog.FileName, token));
        }); export.IsEnabled = lastScan is not null;
        var exportSection = Card("Export");
        exportSection.Children.Add(Note("Exports the results currently shown in File scanner. The file includes local paths."));
        exportSection.Children.Add(Row(export));
    }
    private void QuarantinePage()
    {
        var body = Card("Sentinel quarantine");
        body.Children.Add(Note("Review encrypted backups before restoring or removing them. Restoring a detected file can expose the threat again.", null));
        var table = Table(("Original file", "OriginalPath", 3), ("Source", "SourceRemoved", 1), ("Detected", "Reason", 3));
        var emptyMessage = "Quarantine is empty. Exact detections can be moved here from the File scanner.";
        try { table.ItemsSource = vault.List(); } catch (Exception ex) { emptyMessage = "Quarantine could not be read. Review the error above."; body.Children.Add(Note(ex.Message, "Warning")); }
        EmptyTable(body, table, emptyMessage);
        body.Children.Add(Row(QuietButton("Refresh", () => ShowPage("Quarantine")), WhenSelected(Button("Restore selected…", () => {
            if (table.SelectedItem is not QuarantineEntry entry) { StatusText = "Select a quarantine item."; return; }
            if (IsAdmin) { StatusText = "Use a standard user session for file restoration."; return; }
            if (MessageBox.Show(this, "Restore this detected file to a new location?\n\n" + entry.Reason + "\n\nRestoring can expose the threat again. The backup remains in quarantine; existing files will not be overwritten.", "Restore quarantined file", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            var dialog = new SaveFileDialog { FileName = Path.GetFileName(entry.OriginalPath), OverwritePrompt = false };
            if (dialog.ShowDialog() == true) _ = Run("Restore quarantined file", token => vault.RestoreAsync(entry.Id, dialog.FileName, token));
        }), table, _ => !IsAdmin), WhenSelected(DangerButton("Delete backup permanently…", () => {
            if (table.SelectedItem is not QuarantineEntry entry) { StatusText = "Select a quarantine item."; return; }
            if (MessageBox.Show(this, "Permanently delete this encrypted backup and its recovery key?\n\n" + entry.OriginalPath, "Delete quarantine backup", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) _ = Run("Delete quarantine backup", _ => { vault.Delete(entry.Id); table.ItemsSource = vault.List(); return Task.CompletedTask; });
        }), table)));
        var storage = AdvancedCard("Backup storage & recovery");
        storage.Children.Add(Note("Backups use authenticated AES-256-GCM chunks with keys protected for your Windows user by DPAPI. A backup is committed before removal. \"Backup only\" means source removal was not confirmed. Original paths stay in local metadata. Lost Windows recovery credentials can make backups unrecoverable. This user-mode vault is not tamper-proof."));
    }
}
