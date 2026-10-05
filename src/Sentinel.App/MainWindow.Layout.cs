using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Sentinel.Core.Protection;

namespace Sentinel.App;

// Page building blocks: unboxed sections, status chips, compact stats, review rows and a responsive inspector split.
public partial class MainWindow
{
    private enum Tone { Neutral, Positive, Warning, Danger }
    private static readonly FontFamily IconFont = new("Segoe MDL2 Assets");

    // Sections are separated by hairlines rather than framed in cards.
    private void Section(UIElement content, bool compact = false, bool? separator = null)
    {
        var line = separator ?? PageBody.Children.Count > 0;
        var border = new Border { BorderThickness = new Thickness(0, line ? 1 : 0, 0, 0), Padding = new Thickness(0, !line ? 0 : compact ? 6 : 22, 0, compact ? 6 : 20), Child = content };
        border.SetResourceReference(Border.BorderBrushProperty, "SeparatorSurface");
        PageBody.Children.Add(border);
    }
    private static TextBlock Heading(string title, int size = 16)
    {
        var heading = Text(title, size, true); heading.Margin = new Thickness(0, 0, 0, 6);
        AutomationProperties.SetHeadingLevel(heading, AutomationHeadingLevel.Level2); return heading;
    }
    private static Grid SectionHeader(string title, UIElement? trailing = null)
    {
        var header = new Grid { Margin = new Thickness(0, 0, 0, 4) };
        header.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        header.Children.Add(Heading(title));
        if (trailing is FrameworkElement element)
        {
            element.VerticalAlignment = VerticalAlignment.Top; element.Margin = new Thickness(16, 0, 0, 0);
            Grid.SetColumn(element, 1); header.Children.Add(element);
        }
        return header;
    }
    private static TextBlock Note(string text, string? color = "Muted")
    {
        var note = Text(text, 12, false, color); note.MaxWidth = 760; note.HorizontalAlignment = HorizontalAlignment.Left; return note;
    }
    private static TextBlock FieldLabel(string text)
    {
        var label = Text(text, 12, true, "Muted"); label.Margin = new Thickness(0, 0, 0, 4); return label;
    }
    private static StackPanel Field(string label, FrameworkElement control)
    {
        var field = new StackPanel { Margin = new Thickness(0, 0, 16, 0) };
        field.Children.Add(FieldLabel(label)); field.Children.Add(control); return field;
    }
    private static TextBlock Glyph(string glyph, double size = 14, string color = "Muted")
    {
        var block = new TextBlock { Text = glyph, FontFamily = IconFont, FontSize = size, TextWrapping = TextWrapping.NoWrap, VerticalAlignment = VerticalAlignment.Center };
        block.SetResourceReference(TextBlock.ForegroundProperty, color); return block;
    }
    private static Border Chip(string label, Tone tone = Tone.Neutral)
    {
        var text = new TextBlock { Text = label, Style = (Style)System.Windows.Application.Current.FindResource("ChipText") };
        return new Border { Child = text, Tag = tone.ToString(), Style = (Style)System.Windows.Application.Current.FindResource("Chip") };
    }
    private static void SetChip(Border chip, string label, Tone tone)
    {
        chip.Tag = tone.ToString(); if (chip.Child is TextBlock text) text.Text = label;
    }

    // Large counts with small labels; the whole group reads as one sentence to assistive technology.
    private static WrapPanel Stats(string summary, params (string Value, string Label, Tone Level)[] stats)
    {
        var panel = new WrapPanel { Margin = new Thickness(0, 6, 0, 6) };
        AutomationProperties.SetName(panel, summary);
        foreach (var (value, label, tone) in stats)
        {
            var item = new StackPanel { Margin = new Thickness(0, 0, 36, 8), MinWidth = 72 };
            var number = Text(value, 22, true, tone switch { Tone.Danger => "Danger", Tone.Warning => "Warning", _ => null }); number.Margin = new Thickness(0);
            var caption = Text(label, 12, false, "Muted"); caption.Margin = new Thickness(0, 0, 0, 0);
            item.Children.Add(number); item.Children.Add(caption); panel.Children.Add(item);
        }
        return panel;
    }
    private static WrapPanel ReportStats(ScanReport report) => Stats(ScanSummary(report),
        (report.Scanned.ToString("N0"), "files checked", Tone.Neutral),
        (report.Detected.ToString("N0"), "detections", report.Detected > 0 ? Tone.Danger : Tone.Neutral),
        (report.Review.ToString("N0"), "to review", report.Review > 0 ? Tone.Warning : Tone.Neutral),
        ((report.Skipped + report.Errors).ToString("N0"), "incomplete", report.Skipped + report.Errors > 0 ? Tone.Warning : Tone.Neutral));

    // One compact review row: icon · title/detail · optional chip · optional action. Rows share hairline separators.
    private static void ListRow(Panel parent, string glyph, string title, string detail, UIElement? chip = null, UIElement? action = null)
    {
        var row = new Grid { MinHeight = 36 };
        row.ColumnDefinitions.Add(new() { Width = new GridLength(32) });
        row.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        var icon = Glyph(glyph, 16); icon.VerticalAlignment = VerticalAlignment.Top; icon.Margin = new Thickness(0, 2, 0, 0);
        var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var name = Text(title, 13, true); name.Margin = new Thickness(0);
        var description = Text(detail, 12, false, "Muted"); description.Margin = new Thickness(0, 2, 0, 0);
        text.Children.Add(name); text.Children.Add(description);
        Grid.SetColumn(text, 1); row.Children.Add(icon); row.Children.Add(text);
        if (chip is FrameworkElement c) { c.Margin = new Thickness(16, 0, 0, 0); c.VerticalAlignment = VerticalAlignment.Center; Grid.SetColumn(c, 2); row.Children.Add(c); }
        if (action is FrameworkElement a) { a.Margin = new Thickness(12, 0, 0, 0); a.VerticalAlignment = VerticalAlignment.Center; Grid.SetColumn(a, 3); row.Children.Add(a); }
        var border = new Border { BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 6, 0, 6), Child = row };
        border.SetResourceReference(Border.BorderBrushProperty, "SeparatorSurface");
        parent.Children.Add(border);
    }

    // Review tools: table on the left, selected-item inspector on the right when there is room; stacked otherwise.
    private static Grid Split(FrameworkElement main, FrameworkElement side, double breakpoint = 820, double sideWidth = 320)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        var sideColumn = new ColumnDefinition { Width = new GridLength(0) }; grid.ColumnDefinitions.Add(sideColumn);
        grid.RowDefinitions.Add(new() { Height = GridLength.Auto }); grid.RowDefinitions.Add(new() { Height = GridLength.Auto });
        grid.Children.Add(main); grid.Children.Add(side);
        bool? wide = null;
        void Arrange(double width)
        {
            var next = width >= breakpoint; if (wide == next) return; wide = next;
            sideColumn.Width = next ? new GridLength(sideWidth + 20) : new GridLength(0);
            Grid.SetColumn(side, next ? 1 : 0); Grid.SetRow(side, next ? 0 : 1);
            side.Margin = next ? new Thickness(20, 0, 0, 0) : new Thickness(0, 12, 0, 0);
        }
        Arrange(0); grid.SizeChanged += (_, e) => Arrange(e.NewSize.Width);
        return grid;
    }
    private static Border Inspector(string title, params UIElement[] children)
    {
        var body = new StackPanel();
        var heading = Text(title, 13, true); heading.Margin = new Thickness(0, 0, 0, 8);
        AutomationProperties.SetHeadingLevel(heading, AutomationHeadingLevel.Level3);
        body.Children.Add(heading);
        foreach (var child in children) body.Children.Add(child);
        var panel = new Border { Padding = new Thickness(16, 14, 16, 10), CornerRadius = new CornerRadius(8), BorderThickness = new Thickness(1), Child = body, VerticalAlignment = VerticalAlignment.Top };
        panel.SetResourceReference(Border.BackgroundProperty, "PanelSurface"); panel.SetResourceReference(Border.BorderBrushProperty, "PanelBorder");
        return panel;
    }
    private static TextBox Readout(string name, double maxHeight = 160)
    {
        var box = new TextBox { Style = (Style)System.Windows.Application.Current.FindResource("Readout"), MaxHeight = maxHeight, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        AutomationProperties.SetName(box, name); return box;
    }
    private Button DangerButton(string label, Action action)
    {
        var button = Button(label, action); button.Style = (Style)FindResource("Danger"); return button;
    }
    // A button with a small leading glyph; the text stays the accessible name.
    private Button IconButton(string glyph, string label, Action action, bool primary = false)
    {
        var button = Button(label, action, primary);
        var content = new StackPanel { Orientation = Orientation.Horizontal };
        var icon = new TextBlock { Text = glyph, FontFamily = IconFont, FontSize = 13, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 1, 8, 0), TextWrapping = TextWrapping.NoWrap };
        var text = new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.NoWrap };
        foreach (var part in new[] { icon, text }) { part.SetBinding(TextBlock.ForegroundProperty, new Binding("Foreground") { RelativeSource = new(RelativeSourceMode.FindAncestor, typeof(Button), 1) }); content.Children.Add(part); }
        button.Content = content; AutomationProperties.SetName(button, label); return button;
    }
}

// Maps result values to chip tones for table cells. Unknown values stay neutral.
internal sealed class ToneConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        FileVerdict.KnownThreat => "Danger",
        FileVerdict.TestFile or FileVerdict.NeedsReview or FileVerdict.Skipped or FileVerdict.Error => "Warning",
        FileVerdict => "Neutral",
        null => "Neutral",
        _ => value.ToString() is { } text && text.Contains("urgent", StringComparison.OrdinalIgnoreCase) ? "Danger" : value.ToString()!.Contains("review", StringComparison.OrdinalIgnoreCase) ? "Warning" : "Neutral"
    };
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
