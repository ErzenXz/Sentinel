using System.Net.Http;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
using Sentinel.Core;

namespace Sentinel.App;

public partial class MainWindow : Window
{
    private readonly WindowsSecurity security = new(new PowerShellRunner());
    private readonly HttpClient http = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(3) };
    private readonly CancellationTokenSource lifetime = new();
    private CancellationTokenSource? operation;
    private TaskCompletionSource? operationFinished;
    private readonly Dictionary<string, Button> nav = [];
    private SecuritySnapshot? snapshot;
    private DateTimeOffset? windowsCheckedAt;
    private AiSettings ai = new();
    private string key = "";
    private string page = "Overview";
    private bool busy;
    private bool storageFailed;

    public MainWindow()
    {
        InitializeComponent();
        BuildNavigation();
        InitializeAnnouncements();
        PreviewKeyDown += KeyboardNavigation;
        StopOperation.Click += (_, _) => operation?.Cancel();
        PauseScan.Click += (_, _) => ToggleScanPause();
        Privilege.Text = IsAdmin ? "Administrator session · AI unavailable" : "Standard user session";
        if (IsAdmin) { PrivilegeChip.Tag = "Warning"; PrivilegeGlyph.Text = ""; }
        try { ai = LocalStore.LoadSettings(); key = LocalStore.LoadKey(); }
        catch (Exception) { storageFailed = true; StatusText = "Saved AI settings could not be loaded. Reconfigure them in Settings."; }
        InitializeNetworkReview();
        InitializeProtection();
        InitializeSession();
        Loaded += async (_, _) => { BeginSession(); ShowPage("Overview"); await Refresh(); };
        Closed += (_, _) => { lifetime.Cancel(); DisposeTray(); };
    }
    private static bool IsAdmin { get { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); } }
    private void ShowPage(string name)
    {
        var focusContent = PageBody.IsKeyboardFocusWithin;
        page = name;
        PageTitle.Text = PageLabel(name);
        PageScroll.ScrollToTop();
        PageBody.Children.Clear();
        foreach (var (label, button) in nav)
        {
            var current = label == name;
            button.Tag = current ? "selected" : null;
            button.FontWeight = current ? FontWeights.SemiBold : FontWeights.Normal;
            button.SetResourceReference(Control.ForegroundProperty, current ? "RailSelectedInk" : "RailInk");
            AutomationProperties.SetItemStatus(button, current ? "Current page" : "");
        }
        PageSubtitle.Text = name switch {
            "Overview" => "Scan files with Sentinel and review your Windows protection.",
            "Sentinel engine" => "Check files against known threat hashes, then review results before acting.",
            "Quarantine" => "Encrypted backups of quarantined files. Restore deliberately.",
            "Scan reports" => "Saved results, including canceled and incomplete scans.",
            "Scan" => "Ask Microsoft Defender to check this device.",
            "Applications" => "Running programs and who signed them.",
            "Firewall" => "Which apps use the network, and which are blocked.",
            "AI advisor" => "Optional plain-language explanations. Advisory only.",
            "Activity" => "A local record of actions taken through Sentinel.",
            _ => "Preferences, threat-list trust and optional AI connections."
        };
        switch (name) { case "Overview": Overview(); break; case "Sentinel engine": EnginePage(); break; case "Quarantine": QuarantinePage(); break; case "Scan reports": ReportsPage(); break; case "Scan": Scans(); break; case "Applications": Apps(); break; case "Firewall": Firewall(); break; case "AI advisor": Advisor(); break; case "Activity": Activity(); break; case "Settings": Settings(); break; }
        if (focusContent) PageTitle.Focus();
    }
    private static TextBlock Text(string text, int size = 13, bool bold = false, string? color = null)
    {
        var block = new TextBlock { Text = text, FontSize = size, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
            Margin = new Thickness(0,0,0,8), TextWrapping = TextWrapping.Wrap };
        block.SetResourceReference(TextBlock.ForegroundProperty, Theme.TextResource(color)); return block;
    }
    // A quiet, unframed page section; an optional title becomes a level-2 heading.
    private StackPanel Card(string? title = null, bool compact = false)
    {
        var body = new StackPanel();
        if (title is not null) body.Children.Add(Heading(title));
        Section(body, compact);
        return body;
    }
    private Button Button(string label, Action action, bool primary = false)
    {
        var button = new Button { Content = label };
        if (primary) button.Style = (Style)FindResource("Primary");
        button.Click += (_, _) => action();
        return button;
    }
    private static WrapPanel Row(params UIElement[] children) { var row = new WrapPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0,8,0,0) }; foreach (var child in children) row.Children.Add(child); return row; }
    private static string On(bool? value) => value is null ? "Unavailable" : value.Value ? "On" : "Off · needs attention";
    private static Tone OnTone(bool? value) => value is null ? Tone.Neutral : value.Value ? Tone.Positive : Tone.Warning;
    private static void Fact(Panel panel, string name, string value)
    {
        var row = new Grid { Margin = new Thickness(0, 0, 0, 6) };
        row.ColumnDefinitions.Add(new() { Width = new GridLength(200) });
        row.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        var label = Text(name, 13, false, "Muted"); label.Margin = new Thickness(0, 0, 16, 0);
        var result = Text(value, 13); result.Margin = new Thickness(0); Grid.SetColumn(result, 1);
        row.Children.Add(label); row.Children.Add(result); panel.Children.Add(row);
    }
    private async Task Run(string action, Func<CancellationToken, Task> work, bool audit = true, Func<string>? completedMessage = null)
    {
        if (busy) { StatusText = "An operation is already running. Wait, or stop waiting for it."; return; }
        busy = true;
        PageBody.IsEnabled = false; BusyProgress.Visibility = Visibility.Visible; StopOperation.Visibility = Visibility.Visible;
        BusyProgress.IsIndeterminate = true;
        operationFinished = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = operationFinished;
        operation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        StatusText = action + "…";
        string result;
        try { await work(operation.Token); result = completedMessage?.Invoke() ?? "Completed"; StatusText = completedMessage is null ? action + " completed." : result; }
        catch (OperationCanceledException) { result = "Stopped waiting; a Windows operation may continue"; StatusText = result + "."; }
        catch (Exception ex) { result = "Failed"; StatusText = ex.Message; }
        finally { operation.Dispose(); operation = null; busy = false; PageBody.IsEnabled = true; BusyProgress.IsIndeterminate = false; BusyProgress.Visibility = Visibility.Collapsed; StopOperation.Visibility = Visibility.Collapsed; finished.TrySetResult(); }
        if (audit) { try { LocalStore.Audit(new(DateTimeOffset.Now, action, result)); } catch (Exception) { StatusText += " Activity could not be saved."; } }
    }
    private async Task Refresh() => await Run("Refresh protection status", async token => {
        snapshot = await security.SnapshotAsync(token); windowsCheckedAt = DateTimeOffset.Now;
        if (!lifetime.IsCancellationRequested && page == "Overview") ShowPage(page);
        using var current = Process.GetCurrentProcess();
        Footprint.Text = $"Window process {current.WorkingSet64 / 1024 / 1024} MB";
    }, audit: false);
    private void Overview()
    {
        var detected = engineFindings.Count(x => x.Verdict is Sentinel.Core.Protection.FileVerdict.KnownThreat or Sentinel.Core.Protection.FileVerdict.TestFile);

        // The scan entry point is the one framed surface on Home.
        var entry = new StackPanel();
        if (detected > 0)
        {
            var alert = new Grid { Margin = new Thickness(0, 0, 0, 16) };
            alert.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); alert.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
            var chip = Chip("Needs review", Tone.Danger); chip.Margin = new Thickness(0, 0, 12, 0); chip.VerticalAlignment = VerticalAlignment.Top;
            var message = Text($"{detected:N0} exact detections are waiting for review. Open the scanner to see the evidence and your options.", 13); message.Margin = new Thickness(0);
            Grid.SetColumn(message, 1); alert.Children.Add(chip); alert.Children.Add(message); entry.Children.Add(alert);
        }
        entry.Children.Add(Heading("Check a file or folder", 20));
        entry.Children.Add(Note("Check known threat hashes locally. Keep Windows real-time protection enabled."));
        var actions = Row(IconButton("", "Scan a file…", ChooseScanFile, detected == 0), IconButton("", "Scan a folder…", ChooseScanFolder));
        if (detected > 0) actions.Children.Insert(0, Button("Review detections", ReviewDetections, true));
        actions.Margin = new Thickness(0, 10, 0, 0); entry.Children.Add(actions);
        var shortcuts = Note("Ctrl+O file · Ctrl+Shift+O folder"); shortcuts.Margin = new Thickness(0); entry.Children.Add(shortcuts);
        var frame = new Border { CornerRadius = new CornerRadius(10), BorderThickness = new Thickness(1), Padding = new Thickness(20, 16, 20, 14), Margin = new Thickness(0, 0, 0, 18), Child = entry };
        frame.SetResourceReference(Border.BackgroundProperty, "CardSurface"); frame.SetResourceReference(Border.BorderBrushProperty, "BorderSurface");
        PageBody.Children.Add(frame);

        var status = new StackPanel();
        status.Children.Add(SectionHeader("Protection status", QuietButton("Refresh status", () => _ = Refresh())));
        status.Children.Add(Note((snapshot is null ? "Windows status has not been checked yet." : snapshot.IsHealthy ? "Defender reports no active threats; all three firewall profiles are enabled." : "Some Windows protection settings are off or unavailable. Review the details below.") +
            (windowsCheckedAt is { } checkedAt ? $" Checked {checkedAt:g} · snapshot, not a live status." : "")));
        var defender = snapshot?.Defender?.RealTimeProtectionEnabled;
        ListRow(status, "", "Microsoft Defender", "Windows real-time malware protection", Chip(snapshot is null ? "Not checked" : On(defender), snapshot is null ? Tone.Neutral : OnTone(defender)), QuietButton("Scan with Defender", () => ShowPage("Scan")));
        var profiles = snapshot?.Profiles;
        var firewallReady = snapshot?.FirewallError is null && profiles is { Count: 3 } && profiles.Select(x => x.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 3 && profiles.All(x => x.Enabled);
        var firewallChecked = snapshot is not null && profiles is { Count: > 0 };
        ListRow(status, "", "Windows Firewall", "Domain, private and public profiles", Chip(!firewallChecked ? "Not checked" : firewallReady ? "Profiles enabled" : "Needs review", !firewallChecked ? Tone.Neutral : firewallReady ? Tone.Positive : Tone.Warning), QuietButton("Open firewall", () => ShowPage("Firewall")));
        var missedChanges = monitor?.DroppedEvents > 0;
        ListRow(status, "", "Folder monitor", missedChanges ? "Run a manual folder scan to review missed changes" : "Checks changes while Sentinel is running",
            Chip(missedChanges ? "Missed changes" : monitor?.IsRunning == true ? "Watching a folder" : "Off", missedChanges ? Tone.Warning : Tone.Neutral),
            QuietButton("Manage monitoring", () => OpenSection("Sentinel engine", monitor?.IsRunning == true ? "Folder monitoring · running" : "Folder monitoring · off")));
        ListRow(status, "", "Threat list", FeedStatusNote(), FeedChip(), QuietButton("Threat list & updates", () => OpenSettings("Threat list & trusted server")));
        Section(status, separator: false);

        var latest = Card(compact: true);
        if (lastScan is { } report)
        {
            latest.Children.Add(SectionHeader("Latest Sentinel scan", Note(report.StartedAt.ToLocalTime().ToString("g"))));
            latest.Children.Add(Text(ScanSummary(report), 13, true));
            latest.Children.Add(Note(ScanCoverage(report), report.Canceled || report.Incomplete || report.FeedStale ? "Warning" : "Muted"));
            latest.Children.Add(Row(Button("View results", () => ShowPage("Sentinel engine")), QuietButton("Scan history", () => ShowPage("Scan reports"))));
        }
        else
        {
            latest.Children.Add(Heading("Latest Sentinel scan"));
            latest.Children.Add(Note("No saved scan yet. Choose a file or folder above to get started."));
        }
        if (engineError is not null) latest.Children.Add(Note(engineError, "Warning"));

        var health = AdvancedCard("Windows protection details");
        Fact(health, "Real-time protection", On(snapshot?.Defender?.RealTimeProtectionEnabled));
        Fact(health, "Behavior monitoring", On(snapshot?.Defender?.BehaviorMonitorEnabled));
        Fact(health, "Tamper protection", On(snapshot?.Defender?.IsTamperProtected));
        Fact(health, "Defender mode", snapshot?.Defender?.AMRunningMode ?? "Not checked");
        Fact(health, "Defender intelligence", snapshot?.Defender is { } d ? $"{d.AntivirusSignatureVersion} · {d.AntivirusSignatureAge} days old" : "Not checked");
        foreach (var profile in snapshot?.Profiles ?? []) Fact(health, profile.Name + " firewall", On(profile.Enabled));
        if (snapshot?.Profiles.Count == 0) Fact(health, "Windows Firewall", "Could not be checked");
        foreach (var error in new[] { snapshot?.DefenderError, snapshot?.FirewallError, snapshot?.ThreatError }.OfType<string>()) health.Children.Add(Note(error, "Warning"));
        if (snapshot is null) health.Children.Add(Note("Refresh status to read the Windows protection settings.", null));
        else if (snapshot.ThreatError is not null) health.Children.Add(Note("Defender history could not be read. Review it in Windows Security.", null));
        else if (snapshot.Threats.Count == 0) health.Children.Add(Note("No Defender threat records returned. This does not guarantee every file is safe."));
        else foreach (var threat in snapshot.Threats) health.Children.Add(Text($"{threat.ThreatName} · {(threat.IsActive ? "Active — review now" : "Historical")} · severity {threat.SeverityID}"));
        health.Children.Add(Row(Button("Open Windows Security", () => OpenUri("windowsdefender:"))));
    }
    private async Task Scan(ScanKind kind, string? path = null) => await Run(kind + " Defender scan", async token => {
        await security.ScanAsync(kind, path, token);
        snapshot = await security.SnapshotAsync(token); windowsCheckedAt = DateTimeOffset.Now;
        if (page == "Overview") ShowPage(page);
    });
    private void Scans()
    {
        var body = Card("Run a Defender scan");
        body.Children.Add(Note("Windows chooses the scan workload. Scans and updates may require an administrator session."));
        var options = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        ListRow(options, "", "Quick scan", "Checks common malware locations.", null, Button("Quick scan", () => _ = Scan(ScanKind.Quick), true));
        ListRow(options, "", "Full scan", "Checks the whole device and can take hours.", null, Button("Full scan", () => _ = Scan(ScanKind.Full)));
        var custom = new StackPanel { Orientation = Orientation.Horizontal };
        foreach (var choice in new[] {
            Button("Choose file…", () => { var dialog = new OpenFileDialog(); if (dialog.ShowDialog() == true) _ = Scan(ScanKind.Custom, dialog.FileName); }),
            Button("Choose folder…", () => { var dialog = new OpenFolderDialog(); if (dialog.ShowDialog() == true) _ = Scan(ScanKind.Custom, dialog.FolderName); }) })
        { choice.Margin = new Thickness(8, 0, 0, 0); custom.Children.Add(choice); }
        ListRow(options, "", "Scan one file or folder", "Defender checks only the item you choose.", null, custom);
        body.Children.Add(options);
        var controls = Card("Keep protection current");
        controls.Children.Add(Note("The app reports Windows errors if policy or another antivirus prevents an operation. Stop waiting closes Sentinel's scan request; Defender may continue scanning. Manage remediation, quarantine and restore in Windows Security."));
        controls.Children.Add(Row(Button("Update signatures", () => _ = Run("Update signatures", t => security.UpdateSignaturesAsync(t))), Button("Open Windows Security", () => OpenUri("windowsdefender:")), Button("Protection & quarantine", () => OpenUri("windowsdefender://threat"))));
    }
    private static DataGrid Table(params (string Header, string Property, double Width)[] columns)
    {
        var grid = new DataGrid { MaxHeight = 380, MinHeight = 120 };
        foreach (var col in columns)
        {
            var width = new DataGridLength(col.Width, DataGridLengthUnitType.Star);
            if (col.Property is "Verdict" or "Priority")
            {
                // Result columns render as compact status chips; the visible text remains the converted label.
                var chip = new FrameworkElementFactory(typeof(Border));
                chip.SetValue(FrameworkElement.StyleProperty, System.Windows.Application.Current.FindResource("Chip"));
                chip.SetValue(FrameworkElement.MarginProperty, new Thickness(12, 0, 4, 0));
                chip.SetBinding(FrameworkElement.TagProperty, new Binding(col.Property) { Converter = new ToneConverter() });
                var label = new FrameworkElementFactory(typeof(TextBlock));
                label.SetValue(FrameworkElement.StyleProperty, System.Windows.Application.Current.FindResource("ChipText"));
                label.SetBinding(TextBlock.TextProperty, new Binding(col.Property) { Converter = col.Property == "Verdict" ? new FindingLabelConverter() : null, ConverterParameter = col.Property });
                chip.AppendChild(label);
                grid.Columns.Add(new DataGridTemplateColumn { Header = col.Header, Width = width, MinWidth = col.Property == "Verdict" ? 124 : 112, SortMemberPath = col.Property, CellTemplate = new DataTemplate { VisualTree = chip },
                    ClipboardContentBinding = new Binding(col.Property) { Converter = col.Property == "Verdict" ? new FindingLabelConverter() : null, ConverterParameter = col.Property } });
                continue;
            }
            grid.Columns.Add(new DataGridTextColumn { Header = col.Header, Binding = new Binding(col.Property) { Converter = col.Property is "SourceRemoved" or "Incomplete" ? new FindingLabelConverter() : null, ConverterParameter = col.Property, StringFormat = col.Property is "Time" or "StartedAt" ? "{0:g}" : null }, Width = width,
                MinWidth = col.Property switch { "ProcessId" or "OwningProcess" or "RemotePort" => 64, "NonLocal" => 84, "Listeners" => 80, _ => 20 }, ElementStyle = (Style)System.Windows.Application.Current.FindResource("TableText") });
        }
        return grid;
    }
    private void Apps()
    {
        var body = Card();
        var table = Table(("Application", "Name", 2), ("Signature", "Signature", 1), ("Publisher", "Publisher", 3));
        List<AppRecord> apps = [];
        body.Children.Add(SectionHeader("Running applications", Button("Inspect running apps", () => _ = Run("Inspect running apps", async token => { apps = await security.AppsAsync(token); table.ItemsSource = apps; }), true)));
        body.Children.Add(Note("On-demand snapshot of accessible executable paths. Windows may hide protected processes. A signature identifies a publisher; it is not a malware verdict."));
        var search = new TextBox { MinWidth = 260, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(search, "Filter applications");
        body.Children.Add(Row(Field("Filter by app name or publisher", search)));
        var main = new StackPanel(); EmptyTable(main, table, "No applications shown. Inspect running apps, or change the filter.");
        search.TextChanged += (_, _) => table.ItemsSource = apps.Where(a => (a.Name + a.Publisher).Contains(search.Text, StringComparison.OrdinalIgnoreCase)).ToList();
        var detail = Readout("Selected application path"); detail.Text = "Select an application to see its executable path.";
        table.SelectionChanged += (_, _) => detail.Text = table.SelectedItem is AppRecord a ? a.Path : "Select an application to see its executable path.";
        body.Children.Add(Split(main, Inspector("Selected application", detail, Row(
            WhenSelected(Button("Scan selected", () => { if (table.SelectedItem is AppRecord a) _ = Scan(ScanKind.Custom, a.Path); else StatusText = "Select an application first."; }), table),
            WhenSelected(DangerButton("Block network…", () => { if (table.SelectedItem is AppRecord a) Block(a.Path); else StatusText = "Select an application first."; }), table)))));
    }
    private void Block(string path)
    {
        if (MessageBox.Show(this, "Block all outbound network connections for this executable?\n\n" + path + "\n\nThis can interrupt updates and app services. You can remove this block on the Firewall page. Administrator rights are required.", "Block application", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _ = Run("Create outbound app block", token => security.BlockAppAsync(path, token));
    }
    private void Firewall()
    {
        NetworkReviewCard();
        var body = AdvancedCard("Application network blocks");
        body.Children.Add(Note("Sentinel creates outbound rules for exact executable paths. Windows Firewall enforces them while Sentinel is closed. Domain policy may override local rules."));
        var rules = Table(("Application", "DisplayName", 2), ("Direction", "Direction", 1), ("Executable", "Program", 4));
        body.Children.Add(Row(Button("Load blocks", () => _ = Run("Read firewall rules", async t => rules.ItemsSource = await security.RulesAsync(t))), Button("Block an app…", () => { var dialog = new OpenFileDialog { Filter = "Windows applications|*.exe" }; if (dialog.ShowDialog() == true) Block(dialog.FileName); }), WhenSelected(DangerButton("Remove selected…", () => {
            if (rules.SelectedItem is not FirewallRule r) { StatusText = "Select a Sentinel block first."; return; }
            if (MessageBox.Show(this, "Remove the outbound block for " + r.Program + "?", "Remove block", MessageBoxButton.YesNo) == MessageBoxResult.Yes) _ = Run("Remove outbound app block", async t => { await security.RemoveBlockAsync(r.Name, t); rules.ItemsSource = await security.RulesAsync(t); });
        }), rules)));
        EmptyTable(body, rules, "No blocks shown. Load Sentinel rules to check. Errors appear in the status bar.");
        var connections = AdvancedCard("Raw TCP connections");
        connections.Children.Add(Note("A moment-in-time view. PID identifies the owning process; a remote address alone does not identify a malicious connection."));
        var tcp = Table(("PID", "OwningProcess", 1), ("Remote address", "RemoteAddress", 3), ("Port", "RemotePort", 1), ("State", "State", 2));
        connections.Children.Add(Row(Button("Refresh connections", () => _ = Run("Read TCP connections", async t => tcp.ItemsSource = await security.ConnectionsAsync(t))), Button("Advanced firewall", () => OpenUri("ms-settings:network-status"))));
        EmptyTable(connections, tcp, "No connections shown. Refresh to read the Windows TCP table.");
    }
    private void Advisor()
    {
        var body = Card();
        body.Children.Add(SectionHeader("Ask Sentinel", Chip(IsAdmin ? "Unavailable while elevated" : "Optional · runs only when you ask", IsAdmin ? Tone.Warning : Tone.Neutral)));
        body.Children.Add(Note($"Provider: {ai.Provider} · {(string.IsNullOrWhiteSpace(ai.Model) ? "provider default / model not configured" : ai.Model)}"));
        body.Children.Add(Text("Reviews are advisory. AI can be wrong. Protection continues without AI, and AI cannot make changes to your computer."));
        var consent = new CheckBox { Content = "Include the protection snapshot shown below", IsChecked = false, Margin = new Thickness(0,6,0,4) }; body.Children.Add(consent);
        var preview = new TextBox { Text = AdvisorSnapshot(), IsReadOnly = true, Height = 125, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas"), FontSize = 12 };
        Named(preview, "Protection snapshot sharing preview");
        var disclosure = Details(body, "Preview the optional shared snapshot", preview);
        consent.Checked += (_, _) => disclosure.IsExpanded = true;
        var privacy = Note("Only your question and, if selected, this snapshot go to the configured provider. No file contents, process paths, or API keys are included in the prompt. Review your question for private information."); privacy.Margin = new Thickness(0, 10, 0, 14);
        body.Children.Add(privacy);
        var question = new TextBox { Text = advisorFinding is null ? "What should I check to improve my Windows security?" : "Explain the selected file finding and recommend safe next steps.", Height = 80, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        AutomationProperties.SetName(question, "Question for security advisor"); body.Children.Add(FieldLabel("Your question")); body.Children.Add(question);
        var answer = new TextBox { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 150, MaxHeight = 350, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Named(answer, "Security advisor response");
        body.Children.Add(Row(Button("Ask advisor", () => {
            if (IsAdmin) { StatusText = "Run Sentinel as a standard user for AI. Elevated sessions are reserved for Windows security operations."; return; }
            _ = Run("AI review", async t => { using var deadline = CancellationTokenSource.CreateLinkedTokenSource(t); deadline.CancelAfter(TimeSpan.FromMinutes(3)); answer.Text = await new AiClient(http).AskAsync(ai, key, question.Text, consent.IsChecked == true ? preview.Text : "No device snapshot shared.", deadline.Token); });
        }, true), QuietButton("Configure provider", () => OpenSettings("AI advisor connection"))));
        var response = Card();
        response.Children.Add(SectionHeader("Advisor suggestion", Chip("Verify before acting", Tone.Warning)));
        response.Children.Add(answer);
    }
    private void Activity()
    {
        var body = Card();
        body.Children.Add(SectionHeader("Recent actions", Button("Refresh activity", () => ShowPage("Activity"))));
        body.Children.Add(Note("Saved on this device. Does not store AI prompts, replies, API keys, or file paths. This is an app activity log, not a tamper-proof audit."));
        try { var table = Table(("Time", "Time", 2), ("Action", "Action", 3), ("Result", "Result", 3)); table.ItemsSource = LocalStore.ReadAudit(); EmptyTable(body, table, "No recorded actions yet. Your next completed action will appear here."); } catch (Exception) { body.Children.Add(Note("Activity could not be read.", "Warning")); }
    }
    private void Settings()
    {
        SessionPreferencesCard();
        ThreatServerCard();
        var body = AdvancedCard("AI advisor connection");
        body.IsEnabled = !IsAdmin;
        if (IsAdmin) body.Children.Add(Text("Open a standard user session to configure AI connections.", 13, true));
        if (storageFailed) body.Children.Add(Note("Saved configuration could not be read. Save a new configuration to recover.", "Warning"));
        var provider = new ComboBox { ItemsSource = Enum.GetValues<ProviderKind>(), SelectedItem = ai.Provider, MinWidth = 260, HorizontalAlignment = HorizontalAlignment.Left };
        provider.SelectionChanged += (_, _) => { if (provider.SelectedItem is ProviderKind selected && selected != ai.Provider) StatusText = "Provider changed. Check the endpoint and clear or replace the API key before saving."; };
        Named(provider, "AI advisor provider");
        body.Children.Add(FieldLabel("Connection type")); body.Children.Add(provider);
        var endpoint = Named(new TextBox { Text = ai.Endpoint }, "AI advisor endpoint"); body.Children.Add(FieldLabel("Base endpoint")); body.Children.Add(endpoint);
        var examples = Note("OpenAI-compatible: https://api.openai.com/v1/ · Anthropic: https://api.anthropic.com/ · Ollama: http://127.0.0.1:11434/ · LM Studio: http://127.0.0.1:1234/v1/"); examples.Margin = new Thickness(0, -6, 0, 12); body.Children.Add(examples);
        var model = new ComboBox { Text = ai.Model, IsEditable = true, IsTextSearchEnabled = true }; Named(model, "AI advisor model ID"); body.Children.Add(FieldLabel("Model ID (Codex may use its account default)")); body.Children.Add(model);
        var password = Named(new PasswordBox { Password = key }, "AI advisor API key"); body.Children.Add(FieldLabel("API key (saved securely for this Windows user)")); body.Children.Add(password);
        var discoveryStatus = Note("Discovery requests only model metadata. No security snapshot, question, or inference request is sent.");
        body.Children.Add(Row(Button("Discover available models", () => _ = Run("List AI models", async token => {
            if (IsAdmin) throw new InvalidOperationException("Use a standard user session for AI connections.");
            var selectedProvider = (ProviderKind)provider.SelectedItem;
            var requestedEndpoint = endpoint.Text.Trim();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(20));
            var result = await new AiModelDiscovery(http).ListAsync(selectedProvider, requestedEndpoint, password.Password, deadline.Token);
            if ((ProviderKind)provider.SelectedItem != selectedProvider || endpoint.Text.Trim() != requestedEndpoint) throw new InvalidOperationException("The connection changed while models were being listed. Discover again.");
            var currentModel = model.Text; model.ItemsSource = result.Models; model.Text = currentModel;
            discoveryStatus.Text = $"{result.Models.Count} model IDs listed. {(result.Truncated ? "The list is capped or has another page; enter an ID manually if needed." : "")} Choose a model that supports chat advice; listing does not test inference.";
        }, audit: false))));
        body.Children.Add(discoveryStatus);
        var executable = Named(new TextBox { Text = ai.CodexExecutable }, "Official Codex executable path"); body.Children.Add(FieldLabel("Official codex.exe path — experimental subscription connection")); body.Children.Add(executable);
        body.Children.Add(Row(Button("Choose codex.exe…", () => { var dialog = new OpenFileDialog { Filter = "Codex executable|codex.exe" }; if (dialog.ShowDialog() == true) executable.Text = dialog.FileName; }), Button("Save connection", () => {
            try { var next = new AiSettings((ProviderKind)provider.SelectedItem, endpoint.Text.Trim(), model.Text.Trim(), executable.Text.Trim()); if (next.Provider != ProviderKind.CodexAppServer) AiClient.ValidateEndpoint(next.Endpoint); LocalStore.Save(next, password.Password); ai = next; key = password.Password; storageFailed = false; StatusText = "AI connection saved. Ask the advisor to test it."; } catch (Exception ex) { StatusText = ex.Message; }
        }, true)));
        DecisionSettingsCard();
        var setup = AdvancedCard("Codex subscription setup · experimental");
        setup.Children.Add(Text("Install the official Windows Codex CLI first. Sentinel launches a separate app-server on demand, using a dedicated login and configuration. Subscription access depends on your account. This adapter needs validation on Windows before release."));
        setup.Children.Add(Note("In PowerShell, set CODEX_HOME to the directory below and run the official codex.exe login. No tokens are imported from other applications."));
        setup.Children.Add(Named(new TextBox { Text = CodexAdvisor.Home, IsReadOnly = true }, "Dedicated Codex home directory"));
        setup.Children.Add(Button("Prepare dedicated Codex home", () => { try { CodexAdvisor.PrepareHome(); StatusText = "Dedicated Codex home prepared. See docs/AI-PROVIDERS.md for login commands."; } catch (Exception ex) { StatusText = ex.Message; } }));
        var app = AdvancedCard("About Sentinel & administrator tools");
        app.Children.Add(Text("No Electron, embedded browser, continuous service, telemetry, or bundled language model. Our scanner uses pooled buffers and bounded queues. Folder monitoring and daily scans are optional. Defender provides OS-level real-time protection. Performance comparisons require Windows benchmarks."));
        app.Children.Add(Button("Restart as administrator…", () => {
            if (busy) { StatusText = "Finish the current operation before restarting."; return; }
            if (MessageBox.Show(this, "Restart Sentinel as administrator for firewall changes and privileged Windows operations? AI will be unavailable in that session.", "Administrator session", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
            try { Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", Arguments = "--wait-for-profile" }); exiting = true; Close(); } catch (Exception ex) { StatusText = ex.Message; }
        }));
    }
    private void OpenUri(string uri) { try { Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true }); } catch (Exception ex) { StatusText = ex.Message; } }
}
