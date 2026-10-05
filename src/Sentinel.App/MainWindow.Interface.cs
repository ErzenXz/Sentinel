using System.Collections.Specialized;
using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Input;
using System.Windows.Automation.Peers;
using System.Windows.Threading;
using Microsoft.Win32;
using Sentinel.Core.Protection;

namespace Sentinel.App;

public partial class MainWindow
{
    private DispatcherTimer? announceTimer;
    private string StatusText
    {
        get => Status.Text;
        set { Status.Text = value; if (announceTimer is { IsEnabled: false } timer) timer.Start(); }
    }
    private readonly Dictionary<string, bool> expandedSections = [];
    private (string Route, string Title)? requestedSection;
    private void OpenSection(string route, string title) { requestedSection = (route, title); ShowPage(route); }
    private void OpenSettings(string title) => OpenSection("Settings", title);
    private void ReviewDetections() { findingsSearch = ""; findingsScope = FindingScope.Detections; ShowPage("Sentinel engine"); }
    private void RememberExpansion(Expander expander, string title)
    {
        var section = page + "/" + title;
        expander.IsExpanded = expandedSections.GetValueOrDefault(section);
        expander.Expanded += (_, _) => expandedSections[section] = true;
        expander.Collapsed += (_, _) => expandedSections[section] = false;
        if (requestedSection is { } target && target.Route == page && target.Title == title)
        {
            requestedSection = null; expander.IsExpanded = true;
            expander.Loaded += (_, _) => {
                expander.BringIntoView(new Rect(0, 0, 1, 40));
                expander.MoveFocus(new TraversalRequest(FocusNavigationDirection.First));
            };
        }
    }
    private void KeyboardNavigation(object sender, KeyEventArgs e)
    {
        var modifiers = Keyboard.Modifiers;
        if (e.Key == Key.O && (modifiers == ModifierKeys.Control || modifiers == (ModifierKeys.Control | ModifierKeys.Shift)))
        {
            e.Handled = true;
            if (busy) { StatusText = "Finish the current operation, or use Stop waiting."; return; }
            if (modifiers.HasFlag(ModifierKeys.Shift)) ChooseScanFolder(); else ChooseScanFile();
        }
        else if (e.Key == Key.F6 && modifiers is ModifierKeys.None or ModifierKeys.Shift)
        {
            e.Handled = true;
            if (Navigation.IsKeyboardFocusWithin || SettingsHost.IsKeyboardFocusWithin) { PageScroll.Focus(); if (PageBody.IsEnabled) PageBody.MoveFocus(new TraversalRequest(FocusNavigationDirection.First)); }
            else nav[page].Focus();
        }
        else if (e.Key == Key.Escape && modifiers == ModifierKeys.None && busy)
        {
            e.Handled = true; operation?.Cancel(); StatusText = "Cancellation requested. Windows operations may continue independently.";
        }
    }
    private static T Named<T>(T element, string name) where T : DependencyObject
    {
        AutomationProperties.SetName(element, name); return element;
    }
    private static string PageLabel(string route) => route switch
    {
        "Overview" => "Home", "Sentinel engine" => "File scanner", "Scan" => "Defender scans",
        "Scan reports" => "Scan history", _ => route
    };

    private void BuildNavigation()
    {
        void Add(string route, string icon, Panel target)
        {
            var content = new Grid();
            content.ColumnDefinitions.Add(new() { Width = new GridLength(28) });
            content.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
            var glyph = new TextBlock { Text = icon, FontFamily = IconFont, FontSize = 14, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.NoWrap };
            glyph.SetBinding(TextBlock.ForegroundProperty, new Binding("Foreground") { RelativeSource = new(RelativeSourceMode.FindAncestor, typeof(Button), 1) });
            var label = new TextBlock { Text = PageLabel(route), VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
            label.SetBinding(TextBlock.ForegroundProperty, new Binding("Foreground") { RelativeSource = new(RelativeSourceMode.FindAncestor, typeof(Button), 1) });
            Grid.SetColumn(label, 1); content.Children.Add(glyph); content.Children.Add(label);
            var button = new Button { Content = content, Style = (Style)FindResource("NavButton"), TabIndex = nav.Count };
            AutomationProperties.SetName(button, PageLabel(route));
            button.Click += (_, _) => ShowPage(route);
            button.PreviewKeyDown += (_, e) => {
                if (Keyboard.Modifiers != ModifierKeys.None || e.Key is not (Key.Up or Key.Down or Key.Home or Key.End)) return;
                var buttons = nav.Values.ToList(); var index = buttons.IndexOf(button);
                var next = e.Key switch { Key.Home => 0, Key.End => buttons.Count - 1, Key.Up => Math.Max(0, index - 1), _ => Math.Min(buttons.Count - 1, index + 1) };
                buttons[next].Focus(); e.Handled = true;
            };
            nav[route] = button; target.Children.Add(button);
        }
        void Group(string title, params (string Route, string Icon)[] items)
        {
            // Rail headings use rail tokens so page text colors never apply on the dark rail.
            var heading = new TextBlock { Text = title, FontSize = 11, FontWeight = FontWeights.SemiBold, Margin = new Thickness(12, 16, 0, 6), TextWrapping = TextWrapping.NoWrap };
            heading.SetResourceReference(TextBlock.ForegroundProperty, "RailMuted");
            Navigation.Children.Add(heading);
            foreach (var (route, icon) in items) Add(route, icon, Navigation);
        }
        Group("PROTECT", ("Overview", "\uE80F"), ("Sentinel engine", "\uE721"), ("Firewall", "\uE774"), ("Applications", "\uE71D"), ("Scan", "\uE83D"));
        Group("REVIEW", ("Quarantine", "\uE72E"), ("Scan reports", "\uE81C"), ("AI advisor", "\uE8F2"), ("Activity", "\uE9D9"));
        Add("Settings", "\uE713", SettingsHost);
    }

    private void InitializeAnnouncements()
    {
        var timer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher) { Interval = TimeSpan.FromSeconds(1.5) };
        announceTimer = timer;
        timer.Tick += (_, _) => {
            timer.Stop();
            if (AutomationPeer.ListenerExists(AutomationEvents.LiveRegionChanged))
                UIElementAutomationPeer.CreatePeerForElement(Status)?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
        };
        Closed += (_, _) => { timer.Stop(); announceTimer = null; };
    }

    // Worker progress replaces a single slot, so large scans cannot flood the UI dispatcher.
    private sealed class LatestScanProgress : IProgress<ScanProgress>, IDisposable
    {
        private ScanProgress? latest;
        private readonly DispatcherTimer timer;
        private readonly Action<ScanProgress> apply;
        public LatestScanProgress(Dispatcher dispatcher, Action<ScanProgress> apply)
        {
            this.apply = apply;
            timer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromMilliseconds(200) };
            timer.Tick += (_, _) => Flush(); timer.Start();
        }
        public void Report(ScanProgress value) => Interlocked.Exchange(ref latest, value);
        private void Flush() { if (Interlocked.Exchange(ref latest, null) is { } value) apply(value); }
        public void Dispose() { timer.Stop(); Flush(); }
    }

    private Expander Details(Panel parent, string title, params UIElement[] elements)
    {
        var body = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
        foreach (var element in elements) body.Children.Add(element);
        var expander = new Expander { Header = title, Content = body, FontSize = 13, Margin = new Thickness(0, 8, 0, 0) };
        RememberExpansion(expander, title); parent.Children.Add(expander); return expander;
    }

    // Advanced material is a disclosure row in the page's hairline list, not a framed card.
    private StackPanel AdvancedCard(string title)
    {
        var body = new StackPanel { Margin = new Thickness(0, 6, 0, 10) };
        var expander = new Expander { Header = title, Content = body };
        RememberExpansion(expander, title); Section(expander, compact: true); return body;
    }

    // Tables sit in a single hairline frame; an explicit empty state replaces a blank grid.
    private static void EmptyTable(Panel parent, DataGrid table, string message)
    {
        var note = Text(message, 13, false, "Muted"); note.Margin = new Thickness(0); note.VerticalAlignment = VerticalAlignment.Center;
        var icon = Glyph("", 14); icon.Margin = new Thickness(0, 0, 12, 0);
        var content = new DockPanel(); DockPanel.SetDock(icon, Dock.Left); content.Children.Add(icon); content.Children.Add(note);
        var placeholder = new Border { Padding = new Thickness(16, 20, 16, 20), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Margin = new Thickness(0, 8, 0, 8), Child = content };
        placeholder.SetResourceReference(Border.BorderBrushProperty, "SeparatorSurface");
        var frame = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(1), Margin = new Thickness(0, 8, 0, 8), Child = table };
        frame.SetResourceReference(Border.BorderBrushProperty, "BorderSurface"); frame.SetResourceReference(Border.BackgroundProperty, "CardSurface");
        parent.Children.Add(placeholder); parent.Children.Add(frame);
        void Update() { var empty = table.Items.Count == 0; placeholder.Visibility = empty ? Visibility.Visible : Visibility.Collapsed; frame.Visibility = empty ? Visibility.Collapsed : Visibility.Visible; }
        ((INotifyCollectionChanged)table.Items).CollectionChanged += (_, _) => Update(); Update();
    }

    private static Button WhenSelected(Button button, DataGrid table, Func<object, bool>? allowed = null)
    {
        void Update() => button.IsEnabled = table.SelectedItem is { } item && (allowed?.Invoke(item) ?? true);
        table.SelectionChanged += (_, _) => Update(); Update(); return button;
    }

    private Button QuietButton(string label, Action action)
    {
        var button = Button(label, action); button.Style = (Style)FindResource("Quiet"); return button;
    }

    private void ChooseScanFile()
    {
        var dialog = new OpenFileDialog { Title = "Choose a file to scan with Sentinel" };
        if (dialog.ShowDialog(this) != true) return;
        ShowPage("Sentinel engine"); StartEngineScan(dialog.FileName);
    }
    private void ChooseScanFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder to scan with Sentinel" };
        if (dialog.ShowDialog(this) != true) return;
        ShowPage("Sentinel engine"); StartEngineScan(dialog.FolderName);
    }

    private static string ScanSummary(ScanReport report) => $"{report.Scanned:N0} files checked · {report.Detected:N0} detections · {report.Review:N0} to review · {report.Skipped + report.Errors:N0} incomplete";
    private static string ScanCoverage(ScanReport report) =>
        (report.Canceled ? "Canceled — completed findings were saved." : report.Incomplete ? "Incomplete — some items or results need another scan." : "Finished within scanner limits. No known match does not prove safety.") +
        (report.FeedStale ? " The threat list was stale during this scan." : "");
}

internal sealed class FindingLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is bool flag ? parameter as string == "SourceRemoved" ? flag ? "Removed" : "Backup only" : flag ? "Incomplete" : "Finished" : value is FileVerdict verdict ? verdict switch
    {
        FileVerdict.NoKnownMatch => "No known match", FileVerdict.KnownThreat => "Known threat", FileVerdict.TestFile => "Test detection",
        FileVerdict.NeedsReview => "Review", FileVerdict.Skipped => "Skipped", FileVerdict.Error => "Error", _ => verdict.ToString()
    } : value;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
