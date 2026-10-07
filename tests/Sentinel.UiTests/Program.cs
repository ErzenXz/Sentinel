using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Sentinel.App;
using Sentinel.Core;
using Sentinel.Core.Protection;

internal static partial class Program
{
    private static readonly List<object> checks = [];
    private static readonly List<object> captures = [];
    private static readonly List<object> layoutIssues = [];
    private static readonly List<string> failures = [];
    private static readonly BindingErrors bindingErrors = new();
    private static string output = "";
    private static object? idle;
    private static object? retention;
    private static readonly List<object> resourceSamples = [];
    private static bool profileRun;
    private static string rendering = "software";
    private static int exitCode = 1;
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private static readonly string[] pages = ["Home", "File scanner", "Firewall", "Applications", "Defender scans", "Quarantine", "Scan history", "AI advisor", "Activity", "Settings"];

    [STAThread]
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("Native WPF verification requires Windows."); return 1; }
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
        profileRun = args.Contains("--profile");
        var afterVerification = args.Contains("--after-verification");
        var renderOption = Array.IndexOf(args, "--render");
        if (renderOption >= 0)
        {
            if (!profileRun || renderOption + 1 >= args.Length || args[renderOption + 1] is not ("default" or "software"))
                throw new ArgumentException("Use --profile --render default|software.");
            rendering = args[renderOption + 1];
        }
        if (afterVerification && !profileRun) throw new ArgumentException("Use --after-verification only with --profile.");
        var option = Array.IndexOf(args, "--output");
        output = Path.GetFullPath(option >= 0 && option + 1 < args.Length ? args[option + 1] : "artifacts/native-ui");
        Directory.CreateDirectory(output);
        using var watchdog = new System.Threading.Timer(_ => {
            File.WriteAllText(Path.Combine(output, "timeout.txt"), "Native verification exceeded its three-minute runtime deadline. See progress.txt and the CI log.\n");
            Environment.Exit(1);
        }, null, TimeSpan.FromMinutes(3), Timeout.InfiniteTimeSpan);
        Stage("Creating the isolated WPF application");
        var temporary = Path.Combine(AppContext.BaseDirectory, "ui-fixtures-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        var app = new Sentinel.App.App(verificationStartup: true) { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.InitializeComponent();
        if (rendering == "software") RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
        Theme.Apply();
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Error;
        PresentationTraceSources.DataBindingSource.Listeners.Add(bindingErrors);
        using var profile = LocalStore.UseTemporaryProfile(temporary);
        try
        {
            // Fixture I/O must not capture a dispatcher context before its pump starts.
            Task.Run(() => SeedReport(temporary)).GetAwaiter().GetResult();
            Stage("Constructing the fixture window");
            var runner = new FixtureRunner { BlockReads = !profileRun || afterVerification };
            var window = new MainWindow(runner) { Title = "Sentinel — native Windows UI verification — fixture data", Width = 960, Height = 680 };
            app.MainWindow = window;
            window.Show();
            Stage("Starting the dispatcher");
            window.Dispatcher.BeginInvoke(new Action(async () => {
                try
                {
                    if (!profileRun || afterVerification) await Verify(window, runner, temporary);
                    else
                    {
                        await Until(() => !Field<bool>(window, "busy") && runner.Calls == 3, "Fixture startup did not settle");
                        Check("Fresh fixture startup finishes without OS mutation requests", runner.UnexpectedCalls.IsEmpty);
                    }
                    if (profileRun) await ProfileResources(window);
                }
                catch (Exception ex) { failures.Add("Unexpected verification error: " + ex); }
                finally
                {
                    try
                    {
                        window.Close();
                        await Until(() => app.Windows.Count == 0, "Window shutdown did not settle");
                        Check("Shutdown closes the window and settles pending work", app.Windows.Count == 0);
                    }
                    catch (Exception ex) { failures.Add("Shutdown: " + ex.Message); }
                    exitCode = failures.Count == 0 && layoutIssues.Count == 0 && bindingErrors.Messages.Count == 0 ? 0 : 1;
                    WriteReport(runner);
                    app.Shutdown(exitCode);
                }
            }), DispatcherPriority.ApplicationIdle);
            app.Run();
        }
        finally
        {
            PresentationTraceSources.DataBindingSource.Listeners.Remove(bindingErrors);
            if (app.Windows.Count > 0) app.Shutdown(1);
            Directory.Delete(temporary, recursive: true);
        }
        return exitCode;
    }
    private static void Stage(string message)
    {
        Console.WriteLine(message);
        File.AppendAllText(Path.Combine(output, "progress.txt"), DateTimeOffset.UtcNow.ToString("O") + " " + message + "\n");
    }
    private static void Check(string name, bool passed, object? details = null)
    {
        checks.Add(new { name, passed, details });
        Console.WriteLine((passed ? "PASS " : "FAIL ") + name);
        if (!passed) failures.Add(name);
    }
    private static T Field<T>(MainWindow window, string name) => (T)(typeof(MainWindow).GetField(name, Private)?.GetValue(window) ?? throw new MissingFieldException(name));
    private static void InvokePrivate(MainWindow window, string name, params object[] args) => (typeof(MainWindow).GetMethod(name, Private) ?? throw new MissingMethodException(name)).Invoke(window, args);
    private static void Status(MainWindow window, string message) => typeof(MainWindow).GetProperty("StatusText", Private)!.SetValue(window, message);
    private static IEnumerable<T> Descendants<T>(DependencyObject element) where T : DependencyObject
    {
        if (element is T match) yield return match;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(element); i++)
            foreach (var child in Descendants<T>(VisualTreeHelper.GetChild(element, i))) yield return child;
    }
    private static IEnumerable<T> LogicalDescendants<T>(DependencyObject element) where T : DependencyObject
    {
        if (element is T match) yield return match;
        foreach (var child in LogicalTreeHelper.GetChildren(element).OfType<DependencyObject>())
            foreach (var descendant in LogicalDescendants<T>(child)) yield return descendant;
    }
    private static bool HasAncestor<T>(DependencyObject element) where T : DependencyObject
    {
        for (var parent = VisualTreeHelper.GetParent(element); parent is not null; parent = VisualTreeHelper.GetParent(parent)) if (parent is T) return true;
        return false;
    }
    private static string Name(Button button) => new ButtonAutomationPeer(button).GetName();
    private static Button FindButton(MainWindow window, string name) => Descendants<Button>(window).First(button => Name(button) == name);
    private static async Task Click(Button button)
    {
        if (!button.IsEnabled) throw new InvalidOperationException("The requested verification action is disabled: " + Name(button));
        var peer = new ButtonAutomationPeer(button);
        ((IInvokeProvider)peer.GetPattern(PatternInterface.Invoke)!).Invoke();
        await Drain();
    }
    private static async Task Navigate(MainWindow window, string name)
    {
        var button = Descendants<Button>(Field<StackPanel>(window, name == "Settings" ? "SettingsHost" : "Navigation")).Single(b => Name(b) == name);
        await Click(button); window.UpdateLayout(); await Drain();
        Check("Navigation selects " + name, Field<TextBlock>(window, "PageTitle").Text == name && AutomationProperties.GetItemStatus(button) == "Current page");
    }
    private static async Task Drain()
    {
        await Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        await Task.Delay(20);
        await Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }
    private static async Task Until(Func<bool> condition, string message)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try { while (!condition()) { await Task.Delay(20, deadline.Token); await Drain(); } }
        catch (OperationCanceledException) { throw new TimeoutException(message); }
    }
    private static void SeedReport(string profile)
    {
        var fixture = Path.Combine(profile, "fixtures"); Directory.CreateDirectory(fixture);
        var file = Path.Combine(fixture, "harmless-demo.bin"); File.WriteAllText(file, "Sentinel harmless native UI fixture\n");
        var findings = new FileFinding[] {
            new(file, FileVerdict.KnownThreat, "UI fixture: exact detection display only; this is a harmless local test file.", new string('A', 64), 34),
            new(Path.Combine(fixture, "document.pdf.exe"), FileVerdict.NeedsReview, "UI fixture: executable with a document-style double extension; review only.", new string('B', 64), 100),
            new(Path.Combine(fixture, "unsupported.7z"), FileVerdict.Skipped, "UI fixture: unsupported archive contents remain incomplete.", new string('C', 64), 200)
        };
        var report = new ScanReport(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(.7), 3, 1, 1, 1, 0, false, false, 334, null, true, findings);
        ScanReports.SaveHistoryAsync(report, Path.Combine(profile, "reports")).GetAwaiter().GetResult();
    }
    private static async Task Verify(MainWindow window, FixtureRunner runner, string profile)
    {
        Stage("Checking startup cancellation");
        await Until(() => Field<bool>(window, "busy"), "Startup fixture refresh did not begin");
        Check("Busy startup disables page actions while cancellation and navigation remain reachable",
            !Field<StackPanel>(window, "PageBody").IsEnabled && Field<Button>(window, "StopOperation").IsVisible
            && Field<Button>(window, "StopOperation").IsEnabled && Field<StackPanel>(window, "Navigation").IsEnabled);
        await Navigate(window, "File scanner");
        Check("Navigation during a pending status read does not enable page actions", !Field<StackPanel>(window, "PageBody").IsEnabled);
        Capture(window, "startup-busy", false);
        await Click(Field<Button>(window, "StopOperation"));
        await Until(() => !Field<bool>(window, "busy"), "Startup cancellation did not settle");
        Check("Cancellation restores controls and reaches all fixture requests", runner.CanceledReads == 3 && Field<StackPanel>(window, "PageBody").IsEnabled);
        runner.BlockReads = false;
        await Navigate(window, "Home"); await Click(FindButton(window, "Refresh status"));
        await Until(() => !Field<bool>(window, "busy"), "Fixture refresh did not finish");
        Check("Only fixture snapshot reads ran; no mutation script was requested", runner.UnexpectedCalls.IsEmpty && runner.Calls == 6);

        Stage("Rendering all pages at both window sizes");
        foreach (var (width, height) in new[] { (1200d, 820d), (960d, 680d) })
        {
            await SetSize(window, width, height);
            foreach (var page in pages)
            {
                await Navigate(window, page);
                if (page == "File scanner")
                {
                    var table = Descendants<DataGrid>(Field<StackPanel>(window, "PageBody")).First();
                    Check("Scanner has retained fixture evidence", table.Items.Count == 3);
                    Check("Scanner starts without an implicit selection or enabled selection actions", table.SelectedItem is null
                        && !FindButton(window, "Quarantine selected…").IsEnabled && !FindButton(window, "Copy SHA-256").IsEnabled && !FindButton(window, "Scan file again").IsEnabled);
                    table.SelectedIndex = 0; await Drain();
                    var admin = IsAdministrator();
                    Check("Quarantine eligibility respects the actual runner privilege", FindButton(window, "Quarantine selected…").IsEnabled == !admin);
                    var evidence = LogicalDescendants<TextBox>(window).Single(t => AutomationProperties.GetName(t) == "Selected finding evidence");
                    Check("Selected full evidence and hash are available", FindButton(window, "Copy SHA-256").IsEnabled && evidence.Text.Contains(new string('A', 64)),
                        new { copyEnabled = FindButton(window, "Copy SHA-256").IsEnabled, evidence = evidence.Text, selected = table.SelectedItem });
                    var search = Descendants<TextBox>(window).Single(t => AutomationProperties.GetName(t) == "Search findings by path, evidence, or SHA-256");
                    search.Text = "no-matching-fixture"; await Drain();
                    Check("Finding search presents an empty view without discarding evidence", table.Items.Count == 0 && Field<ObservableCollection<FileFinding>>(window, "engineFindings").Count == 3);
                    search.Text = ""; await Drain(); table.SelectedIndex = 0; await Drain();
                    FindButton(window, "Scan file again").BringIntoView(); await Drain(); Capture(window, "selected-finding-" + (int)width, true);
                    Field<ScrollViewer>(window, "PageScroll").ScrollToTop(); await Drain();
                }
                if (page == "Firewall")
                {
                    await Expand(window, "Optional AI review · Jev");
                    Check("No network selection can authorize a block or model review", !FindButton(window, "Block selected app…").IsEnabled && !FindButton(window, "Review selected with Jev").IsEnabled);
                    LogicalDescendants<Expander>(window).First(e => e.Header as string == "Optional AI review · Jev").IsExpanded = false;
                    Field<ScrollViewer>(window, "PageScroll").ScrollToTop(); await Drain();
                }
                Capture(window, Slug(page) + "-" + (int)width, true);
            }
        }
        await SetSize(window, 1200, 820);
        await Navigate(window, "File scanner");
        await Expand(window, "Folder monitoring · off"); Capture(window, "monitoring-details", true);
        await Navigate(window, "Settings");
        await Expand(window, "AI advisor connection"); Capture(window, "provider-settings", true);
        await Navigate(window, "File scanner");
        Theme.Apply(true); window.UpdateLayout(); await Drain();
        Check("Forced high-contrast resource path uses Windows system brushes", ReferenceEquals(System.Windows.Application.Current.Resources["Ink"], SystemColors.WindowTextBrush));
        Capture(window, "scanner-system-color-branch", true);
        Theme.Apply(); window.UpdateLayout(); await Drain();

        Stage("Checking selected file rescan"); await VerifySelectedRescan(window, profile);
        Stage("Checking local scan controls"); await VerifyScanControls(window, profile);
        Stage("Checking scanner view retention"); await VerifyRetention(window);
        await Navigate(window, "Home");
        Status(window, "Native Windows verification • harmless fixture data • no real protection setting was changed.");
        if (profileRun) idle = await SampleResources(window, "immediately-after-verification", 3000);
        else
        {
        await Task.Delay(2000); await Drain();
        using var process = Process.GetCurrentProcess(); process.Refresh();
        var start = Stopwatch.GetTimestamp(); var cpu = process.TotalProcessorTime;
        var dispatches = new long[16];
        DispatcherHookEventHandler onDispatch = (_, e) => { var priority = (int)e.Operation.Priority; if (priority >= 0 && priority < dispatches.Length) dispatches[priority]++; };
        window.Dispatcher.Hooks.OperationStarted += onDispatch;
        try { await Task.Delay(3000); }
        finally { window.Dispatcher.Hooks.OperationStarted -= onDispatch; }
        process.Refresh();
        idle = new { description = "Three-second idle UI fixture sample after verification and collection; excludes production PowerShell reads, Defender, AI, on-access drivers and real workloads. Not a comparative AV benchmark.",
            seconds = Stopwatch.GetElapsedTime(start).TotalSeconds, cpuMilliseconds = (process.TotalProcessorTime - cpu).TotalMilliseconds,
            workingSetBytes = process.WorkingSet64, privateBytes = process.PrivateMemorySize64, managedBytes = GC.GetTotalMemory(false), processors = Environment.ProcessorCount,
            dispatcherOperations = dispatches.Select((count, priority) => new { priority = ((DispatcherPriority)priority).ToString(), count }).Where(x => x.count > 0).ToArray() };
        }
        Check("Rendering/navigation never requested an OS write through the injected runner", runner.UnexpectedCalls.IsEmpty);
    }
    private static async Task VerifySelectedRescan(MainWindow window, string profile)
    {
        await Navigate(window, "File scanner");
        var table = Descendants<DataGrid>(Field<StackPanel>(window, "PageBody")).First();
        table.SelectedIndex = 0; await Drain();
        var finding = (FileFinding)table.SelectedItem;
        var replacement = "Harmless current bytes differ from the retained display-only detection. " + new string('x', 400);
        await File.WriteAllTextAsync(finding.Path, replacement);
        Check("Selected rescan is available with whole-file behavior described", FindButton(window, "Scan file again").IsEnabled
            && AutomationProperties.GetHelpText(FindButton(window, "Scan file again")).Contains("whole archive"));
        await Click(FindButton(window, "Scan file again"));
        await Until(() => !Field<bool>(window, "busy"), "Selected rescan did not finish");
        var report = Field<ScanReport>(window, "lastScan");
        Check("Selected rescan reads current bytes and replaces historical detection evidence", report.Scanned == 1 && !report.Incomplete
            && report.Detected == 0 && report.BytesRead == System.Text.Encoding.UTF8.GetByteCount(replacement)
            && Field<ObservableCollection<FileFinding>>(window, "engineFindings").Count == 0);
        var saved = ScanReports.Latest(Path.Combine(profile, "reports"));
        Check("Selected rescan saves current results in history", saved?.StartedAt == report.StartedAt && saved.BytesRead == report.BytesRead);
    }
    private static async Task Expand(MainWindow window, string title)
    {
        var expander = Descendants<Expander>(window).First(e => e.Header as string == title);
        var peer = UIElementAutomationPeer.CreatePeerForElement(expander)!;
        ((IExpandCollapseProvider)peer.GetPattern(PatternInterface.ExpandCollapse)!).Expand();
        await Drain(); expander.BringIntoView(new Rect(0, 0, 1, 40)); await Drain();
        Check("Accessible disclosure expands " + title, expander.IsExpanded);
    }
    private static async Task SetSize(MainWindow window, double width, double height)
    {
        // Hosted displays can cap tracking at 1024x768. Enforce only this fixture's
        // requested size so both production inspector arrangements actually render.
        window.MinWidth = width; window.MinHeight = height;
        window.Width = width; window.Height = height; window.UpdateLayout(); await Drain();
        Check("Native window reaches " + width + " × " + height,
            Math.Abs(window.ActualWidth - width) < 1 && Math.Abs(window.ActualHeight - height) < 1);
    }
    private static async Task VerifyScanControls(MainWindow window, string profile)
    {
        await Navigate(window, "File scanner");
        var folder = Path.Combine(profile, "scan-control-fixtures"); Directory.CreateDirectory(folder);
        var bytes = new byte[1024 * 1024]; Array.Fill(bytes, (byte)'q');
        for (var i = 0; i < 96; i++) await File.WriteAllBytesAsync(Path.Combine(folder, "fixture-" + i + ".bin"), bytes);
        typeof(MainWindow).GetField("scanMode", Private)!.SetValue(window, ScanMode.LowImpact);
        InvokePrivate(window, "StartEngineScan", folder);
        await Until(() => Field<Button>(window, "PauseScan").IsVisible, "Manual scan controls did not appear");
        await Click(Field<Button>(window, "PauseScan"));
        await Until(() => Field<ScanControl>(window, "manualScan").IsPaused, "Pause did not reach the scan control");
        Check("Pause remains available outside disabled scan actions", !Field<StackPanel>(window, "PageBody").IsEnabled && Field<Button>(window, "PauseScan").IsEnabled);
        Check("Paused scan stops the indeterminate animation", !Field<ProgressBar>(window, "BusyProgress").IsIndeterminate && Field<Button>(window, "PauseScan").Content as string == "Resume scan");
        Capture(window, "scan-paused", false);
        await Click(Field<Button>(window, "PauseScan"));
        Check("Resume restores the scan control and progress animation", !Field<ScanControl>(window, "manualScan").IsPaused && Field<ProgressBar>(window, "BusyProgress").IsIndeterminate);
        await Click(Field<Button>(window, "PauseScan")); await Click(Field<Button>(window, "StopOperation"));
        await Until(() => !Field<bool>(window, "busy"), "Cancel while paused did not settle");
        Check("Cancel while paused saves partial status and restores controls", Field<ScanReport>(window, "lastScan").Canceled
            && !Field<Button>(window, "PauseScan").IsVisible && !Field<Button>(window, "StopOperation").IsVisible && Field<StackPanel>(window, "PageBody").IsEnabled);
        var small = Path.Combine(profile, "next-scan.txt"); File.WriteAllText(small, "Harmless next scan fixture");
        InvokePrivate(window, "StartEngineScan", small); await Until(() => !Field<bool>(window, "busy"), "Next scan did not finish");
        Check("A subsequent scan starts with clean control state", !Field<ScanReport>(window, "lastScan").Canceled && Field<ScanReport>(window, "lastScan").Scanned == 1);
    }
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> LeaveScannerView(MainWindow window)
    {
        await Navigate(window, "File scanner");
        var view = Descendants<DataGrid>(Field<StackPanel>(window, "PageBody")).First().ItemsSource;
        var reference = new WeakReference(view);
        await Navigate(window, "Home"); return reference;
    }
    private static async Task VerifyRetention(MainWindow window)
    {
        var references = new List<WeakReference>();
        var before = GC.GetTotalMemory(true);
        for (var i = 0; i < 12; i++) references.Add(await LeaveScannerView(window));
        await Drain(); GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); await Drain(); GC.Collect();
        var alive = references.Count(r => r.IsAlive);
        retention = new { exitedScannerViews = references.Count, retainedScannerViews = alive, managedBytesBefore = before, managedBytesAfter = GC.GetTotalMemory(true) };
        Check("Old scanner collection views detach after navigation", alive == 0);
    }
    private static string Slug(string page) => page.ToLowerInvariant().Replace(' ', '-');
    private static void Capture(MainWindow window, string name, bool inspect)
    {
        Status(window, "Native Windows render • fixture data • verification only; no protection setting changed.");
        window.UpdateLayout(); var root = (FrameworkElement)window.Content;
        if (inspect) InspectLayout(root, name);
        if (inspect) Check("Button text follows its control brush in " + name,
            Descendants<Button>(root).Where(b => b.IsVisible && b.Content is string).All(b => Descendants<TextBlock>(b).Where(t => !string.IsNullOrEmpty(t.Text)).All(t => Equals(t.Foreground, b.Foreground))));
        var width = (int)Math.Ceiling(root.ActualWidth); var height = (int)Math.Ceiling(root.ActualHeight);
        if (width is < 1 or > 4000 || height is < 1 or > 4000) throw new InvalidOperationException("Unexpected render size.");
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        // Window background is outside the client visual; preserve that actual brush.
        var background = new DrawingVisual();
        using (var context = background.RenderOpen()) context.DrawRectangle(window.Background, null, new Rect(0, 0, width, height));
        bitmap.Render(background);
        bitmap.Render(root);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        var path = Path.Combine(output, name + ".png"); using (var stream = File.Create(path)) encoder.Save(stream);
        captures.Add(new { name, file = name + ".png", width, height, logicalWindowWidth = window.Width, logicalWindowHeight = window.Height, fixtureData = true, dpi = 96 });
        Console.WriteLine("CAPTURE " + name + " " + width + "x" + height);
    }
    private static void InspectLayout(FrameworkElement root, string capture)
    {
        foreach (var text in Descendants<TextBlock>(root))
        {
            if (!text.IsVisible || text.ActualWidth <= 0 || string.IsNullOrWhiteSpace(text.Text) || HasAncestor<TextBox>(text) || HasAncestor<PasswordBox>(text)) continue;
            Rect bounds;
            try { bounds = text.TransformToAncestor(root).TransformBounds(new Rect(text.RenderSize)); } catch (InvalidOperationException) { continue; }
            if (bounds.Bottom < 0 || bounds.Top > root.ActualHeight) continue;
            if (bounds.Left < -2 || bounds.Right > root.ActualWidth + 2)
                layoutIssues.Add(new { capture, issue = "Text extends outside the window horizontally", text = text.Text, left = bounds.Left, right = bounds.Right, width = root.ActualWidth });
            if (text.TextWrapping == TextWrapping.NoWrap && text.TextTrimming == TextTrimming.None && !HasAncestor<DataGrid>(text))
            {
                var formatted = new FormattedText(text.Text, CultureInfo.CurrentUICulture, text.FlowDirection,
                    new Typeface(text.FontFamily, text.FontStyle, text.FontWeight, text.FontStretch), text.FontSize, text.Foreground, VisualTreeHelper.GetDpi(text).PixelsPerDip);
                if (formatted.WidthIncludingTrailingWhitespace > text.ActualWidth + 3)
                    layoutIssues.Add(new { capture, issue = "Untrimmed single-line text is clipped", text = text.Text, required = formatted.WidthIncludingTrailingWhitespace, available = text.ActualWidth });
            }
        }
    }
    private static bool IsAdministrator() { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
    private static void WriteReport(FixtureRunner runner)
    {
        var report = new { schemaVersion = 1, renderedAt = DateTimeOffset.UtcNow, commit = Environment.GetEnvironmentVariable("GITHUB_SHA"),
            description = "Actual Windows WPF fixture profile and injected read-only status data. No paid AI or OS protection change. This does not certify native ARM64, Narrator, OS high-contrast, hardware DPI, UAC, DPAPI recovery or enforcement. Resource profiling phases are test-only diagnostics, not comparative AV benchmarks.",
            profileRun, rendering, resourceSamples,
            runtimeConfiguration = new { tieredCompilation = Environment.GetEnvironmentVariable("DOTNET_TieredCompilation") ?? "runtime default" },
            os = RuntimeInformation.OSDescription, architecture = RuntimeInformation.ProcessArchitecture.ToString(), dotnet = Environment.Version.ToString(), elevatedRunner = IsAdministrator(),
            exitCode, checks, captures, layoutIssues, failures, bindingErrors = bindingErrors.Messages.ToArray(),
            fixtureReads = runner.Calls, canceledFixtureReads = runner.CanceledReads, unexpectedScripts = runner.UnexpectedCalls.ToArray(), idle, retention };
        File.WriteAllText(Path.Combine(output, "verification.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Native verification: {checks.Count} checks; {captures.Count} captures; {failures.Count} failures; {layoutIssues.Count} layout issues; {bindingErrors.Messages.Count} binding errors.");
    }
    private sealed class FixtureRunner : IScriptRunner
    {
        public volatile bool BlockReads;
        public int Calls, CanceledReads;
        public ConcurrentQueue<string> UnexpectedCalls { get; } = new();
        public async Task<string> RunAsync(string script, object? parameters = null, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            if (BlockReads)
            {
                try { await Task.Delay(Timeout.Infinite, cancellationToken); }
                catch (OperationCanceledException) { Interlocked.Increment(ref CanceledReads); throw; }
            }
            if (script.Contains("Get-MpComputerStatus", StringComparison.Ordinal)) return JsonSerializer.Serialize(new DefenderStatus(true, true, true, true, "Normal", 0, "Fixture data", null));
            if (script.Contains("Get-NetFirewallProfile", StringComparison.Ordinal)) return JsonSerializer.Serialize(new[] { new FirewallProfile("Domain", true, "Block", "Allow"), new FirewallProfile("Private", true, "Block", "Allow"), new FirewallProfile("Public", true, "Block", "Allow") });
            if (script.Contains("Get-MpThreat", StringComparison.Ordinal)) return "[]";
            UnexpectedCalls.Enqueue(script); throw new InvalidOperationException("The UI fixture does not permit this operation.");
        }
    }
    private sealed class BindingErrors : TraceListener
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public override void Write(string? message) { if (!string.IsNullOrWhiteSpace(message) && Messages.Count < 128) Messages.Enqueue(message); }
        public override void WriteLine(string? message) => Write(message);
    }
}
