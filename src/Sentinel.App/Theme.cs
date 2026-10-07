using System.Windows;
using System.Windows.Media;

namespace Sentinel.App;

internal static class Theme
{
    public static string TextResource(string? color) => color switch {
        "Muted" or "#667975" or "#526B64" => "Muted", "Warning" or "#986131" or "#91762A" => "Warning", "Positive" or "#176B57" => "Positive", "Danger" => "DangerInk", _ => "Ink"
    };
    // Keep these values identical to the initial brushes in App.xaml.
    public static void Apply() => Apply(SystemParameters.HighContrast);
    internal static void Apply(bool high)
    {
        var resources = System.Windows.Application.Current.Resources;
        void Set(string key, string normal, Brush contrast) => resources[key] = high ? contrast : new SolidColorBrush((System.Windows.Media.Color)ColorConverter.ConvertFromString(normal));
        Set("Ink", "#1C1F1D", SystemColors.WindowTextBrush);
        Set("Muted", "#595E58", SystemColors.WindowTextBrush);
        Set("Positive", "#1E6B4D", SystemColors.WindowTextBrush);
        Set("DisabledInk", "#5F635E", SystemColors.GrayTextBrush);
        Set("Warning", "#8A5A12", SystemColors.WindowTextBrush);
        Set("Accent", "#1F5C45", SystemColors.HighlightBrush);
        Set("AccentText", "#FFFFFF", SystemColors.HighlightTextBrush);
        Set("LinkInk", "#1F5C45", SystemColors.HotTrackBrush);
        Set("CanvasSurface", "#F7F6F2", SystemColors.WindowBrush);
        Set("CardSurface", "#FFFFFF", SystemColors.WindowBrush);
        Set("PanelSurface", "#F0EEE8", SystemColors.WindowBrush);
        Set("PanelBorder", "#00000000", SystemColors.WindowTextBrush);
        Set("StatusSurface", "#F2F0EA", SystemColors.WindowBrush);
        Set("ControlSurface", "#EEECE6", SystemColors.ControlBrush);
        Set("HoverSurface", "#F0EEE8", SystemColors.WindowBrush);
        Set("HoverOverlay", "#0F000000", Brushes.Transparent);
        Set("PressedOverlay", "#1F000000", Brushes.Transparent);
        Set("InputSurface", "#FFFFFF", SystemColors.WindowBrush);
        Set("InputBorder", "#8C887F", SystemColors.WindowTextBrush);
        Set("BorderSurface", "#D9D5CC", SystemColors.WindowTextBrush);
        Set("SeparatorSurface", "#E5E2DA", SystemColors.WindowTextBrush);
        Set("AlternateRowSurface", "#FFFFFF", SystemColors.WindowBrush);
        Set("SelectionSurface", "#E2ECE5", SystemColors.HighlightBrush);
        Set("SelectionInk", "#143A2C", SystemColors.HighlightTextBrush);
        Set("FocusOutline", "#1F5C45", SystemColors.WindowTextBrush);
        Set("DangerInk", "#A3271B", SystemColors.WindowTextBrush);
        Set("DangerSurface", "#FAECE9", SystemColors.WindowBrush);
        Set("ChipNeutralSurface", "#ECEAE4", SystemColors.WindowBrush);
        Set("ChipPositiveSurface", "#E3EFE7", SystemColors.WindowBrush);
        Set("ChipWarningSurface", "#F6EAD3", SystemColors.WindowBrush);
        Set("ChipBorder", "#00000000", SystemColors.WindowTextBrush);
        Set("RailSurface", "#1E2320", SystemColors.WindowBrush);
        Set("SidebarSurface", "#1E2320", SystemColors.WindowBrush);
        Set("RailBorder", "#1E2320", SystemColors.WindowTextBrush);
        Set("RailInk", "#D5D9D4", SystemColors.WindowTextBrush);
        Set("RailMuted", "#9AA19B", SystemColors.WindowTextBrush);
        Set("RailHoverSurface", "#2A302C", SystemColors.WindowBrush);
        Set("RailSelectedSurface", "#343B36", SystemColors.HighlightBrush);
        Set("RailSelectedInk", "#FFFFFF", SystemColors.HighlightTextBrush);
        Set("RailIndicator", "#7CC4A0", SystemColors.HighlightTextBrush);
        Set("RailFocus", "#F2F0E8", SystemColors.WindowTextBrush);
        Set("RailBrand", "#7CC4A0", SystemColors.WindowTextBrush);
        resources["PressedOpacity"] = high ? 1d : 0.88d;
        resources["DisabledOpacity"] = 1d;
        resources["HoverOpacity"] = high ? 1d : 0.92d;
    }
}
