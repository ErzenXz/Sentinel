using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core;

namespace Sentinel.App;

public partial class MainWindow
{
    private DecisionSettings decisionSettings = new();
    private string decisionKey = "";
    private string? decisionSetupError;
    private NetworkSnapshot? networkSnapshot;
    private IReadOnlyList<NetworkAppReview> networkApps = [];
    private DecisionReviewService? decisionReviews;
    private DecisionReviewService DecisionReviews => decisionReviews ??= new(new JevClient(http));
    private void InitializeNetworkReview()
    {
        try { var connection = LocalStore.LoadDecision(); decisionSettings = connection.Settings; decisionKey = connection.Key; }
        catch (Exception) { decisionSetupError = "Saved Jev connection could not be read. Reconfigure it in Settings."; }
    }
    private void NetworkReviewCard()
    {
        var body = Card();
        var freshnessChip = Chip("No snapshot");
        void UpdateFreshnessChip(NetworkSnapshot? current)
        {
            if (current is null) SetChip(freshnessChip, "No snapshot", Tone.Neutral);
            else if (current.Truncated) SetChip(freshnessChip, "Incomplete snapshot", Tone.Warning);
            else if (NetworkReview.IsFresh(current, DateTimeOffset.UtcNow)) SetChip(freshnessChip, "Recent snapshot", Tone.Neutral);
            else SetChip(freshnessChip, "Refresh needed", Tone.Warning);
        }
        UpdateFreshnessChip(networkSnapshot);
        body.Children.Add(SectionHeader("Applications on your network", freshnessChip));
        body.Children.Add(Note("Refresh to see a local TCP snapshot, then select an app to inspect its publisher or review a network block. No AI is needed."));
        string DescribeSnapshot(NetworkSnapshot? current)
        {
            if (current is null) return "No network snapshot yet. Refresh to get started.";
            var policy = NetworkReview.GlobalDecision(current);
            return $"Last read {current.CapturedAt.ToLocalTime():g} · {current.Connections.Count} TCP records · {(NetworkReview.IsFresh(current, DateTimeOffset.UtcNow) ? "recent snapshot" : "refresh needed before reviewing")}\n{policy.Priority}: {string.Join(" ", policy.Reasons)}" +
                (current.Truncated ? " · Record limit reached; incomplete" : "") +
                string.Concat(new[] { current.ProfileError, current.ConnectionError, current.ProcessError }.OfType<string>().Select(x => " · " + x));
        }
        var freshness = Note(DescribeSnapshot(networkSnapshot), null);
        var grid = Table(("Application", "Name", 3), ("PID", "ProcessId", 1), ("Non-local", "NonLocal", 1), ("Listeners", "Listeners", 1), ("Priority", "Priority", 1));
        grid.ItemsSource = networkApps;
        var filter = new TextBox { MaxLength = 256, Width = 260 };
        System.Windows.Automation.AutomationProperties.SetName(filter, "Search network applications");
        var main = new StackPanel();
        EmptyTable(main, grid, "No network applications shown. Refresh local review, or change the filter.");
        void Refilter() { grid.SelectedItem = null; grid.ItemsSource = networkApps.Where(x => (x.Name + " " + x.ProcessId).Contains(filter.Text, StringComparison.OrdinalIgnoreCase)).ToArray(); }
        filter.TextChanged += (_, _) => Refilter();
        var details = Readout("Selected app evidence", 200);
        var preview = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, Height = 130, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 12 };
        Named(preview, "Jev payload preview");
        NetworkAppReview? selected = null;
        var consent = new CheckBox { Content = "Send exactly this categories/counts preview to my configured Jev provider", IsChecked = false, IsEnabled = !IsAdmin };
        var answer = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MinHeight = 70, MaxHeight = 180, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Named(answer, "Jev review result");
        void Select(NetworkAppReview? app)
        {
            selected = app; consent.IsChecked = false; answer.Text = "";
            details.Text = app is null ? "Select an app to review local evidence." : $"{app.Name} · PID {app.ProcessId}\n{app.Path}\n{app.Priority}: {app.Summary}\nSignature: {app.Evidence.Signature}";
            preview.Text = app is null ? "" : JevClient.Preview(app.Evidence);
        }
        grid.SelectionChanged += (_, _) => Select(grid.SelectedItem as NetworkAppReview); Select(null);
        bool Fresh()
        {
            if (networkSnapshot is not null && NetworkReview.IsFresh(networkSnapshot, DateTimeOffset.UtcNow)) return true;
            StatusText = "Refresh the network snapshot first. Reviews require evidence captured within two minutes."; return false;
        }
        var refresh = Button("Refresh local review", () => _ = Run("Read local network evidence", async token => {
            var elapsed = Stopwatch.StartNew();
            var current = await NetworkCapture.ReadAsync(new PowerShellRunner(), token);
            var assessed = await Task.Run(() => NetworkReview.Assess(current), token);
            networkSnapshot = current; networkApps = assessed; Refilter();
            freshness.Text = DescribeSnapshot(current); UpdateFreshnessChip(current);
            StatusText = $"Local network snapshot read in {elapsed.Elapsed.TotalMilliseconds:F0} ms.";
        }, audit: false), true);
        refresh.VerticalAlignment = VerticalAlignment.Bottom; refresh.Margin = new Thickness(0, 0, 16, 12);
        body.Children.Add(Row(refresh, Field("Filter application name or PID", filter)));
        body.Children.Add(freshness);
        body.Children.Add(Split(main, Inspector("Selected application", details, Row(WhenSelected(Button("Inspect publisher", () => {
            if (selected is not { } app || !Fresh()) { if (selected is null) StatusText = "Select an application first."; return; }
            _ = Run("Inspect network app publisher", async token => {
                var inspected = await NetworkCapture.InspectAsync(new PowerShellRunner(), app, token);
                if (!Fresh()) return;
                var evidence = app.Evidence with { Signature = NetworkReview.SignatureCategory(inspected.Signature) };
                var updated = app with { Evidence = evidence, Decision = NetworkReview.Decide(evidence) };
                networkApps = networkApps.Select(x => x.ProcessId == app.ProcessId ? updated : x).ToArray();
                Refilter(); grid.SelectedItem = updated;
                details.Text += "\nPublisher (local only): " + inspected.Publisher;
            });
        }), grid), WhenSelected(DangerButton("Block selected app…", () => {
            if (selected is not { } app || !Fresh()) { if (selected is null) StatusText = "Select an application first."; return; }
            // Validate the PID/start/path immediately; block scope is still the user-confirmed executable path.
            _ = Run("Validate selected network app", async token => {
                var inspected = await NetworkCapture.InspectAsync(new PowerShellRunner(), app, token);
                if (MessageBox.Show(this, "Create a Windows Firewall outbound block for this exact executable path?\n\n" + inspected.Path + "\n\nThis can interrupt updates/services. It affects future network access for any executable at this path and does not close a listener or prove malware. Administrator rights are required. Remove it using Application network blocks below.", "Review outbound block", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    await security.BlockAppAsync(inspected.Path, token);
            });
        }), grid)))));
        var jev = (StackPanel)Details(body, "Optional AI review · Jev").Content;
        jev.Children.Add(Text("Jev ranks routine / review / urgent from a small typed payload. It cannot block an app, change a rule or lower local warnings. Counts omit executable names/paths, PIDs, remote addresses and publisher text. A provider request may consume your API credits.", 12));
        jev.Children.Add(FieldLabel("Exact payload for the selected app")); jev.Children.Add(preview); jev.Children.Add(consent);
        jev.Children.Add(Row(WhenSelected(Button("Review selected with Jev", () => {
            if (IsAdmin) { StatusText = "Use a standard user session for Jev."; return; }
            if (selected is not { } app) { StatusText = "Select an application first."; return; }
            if (!Fresh()) return;
            if (consent.IsChecked != true) { StatusText = "Review the displayed payload and select the sharing option first."; return; }
            var settings = decisionSettings; var credential = decisionKey;
            _ = Run("Jev firewall decision", async token => {
                var result = await DecisionReviews.ReviewAsync(settings, credential, app.Evidence, token);
                if (!Fresh()) { answer.Text = "Evidence aged out while reviewing. Refresh and review again."; return; }
                if (selected != app) return;
                answer.Text = $"Priority: {result.Priority} · {(result.Cached ? "reused identical review" : "new review")}\n{result.Status}";
                if (result.ModelDecision is { } model) answer.Text += $"\n{model.Model} chose {model.Choice}; reported confidence {model.Confidence:P0}; choice probability {model.Probabilities[model.Choice]:P0}; request {model.Elapsed.TotalMilliseconds:F0} ms. Model confidence is not a safety guarantee.";
            });
        }), grid, _ => !IsAdmin), QuietButton("Configure Jev", () => OpenSettings("Jev firewall review connection")))); jev.Children.Add(answer);
        jev.Children.Add(Note("No background AI polling. Identical successful reviews are cached in memory for two minutes (128-entry cap); provider/model/key changes use separate entries. Failures remain manual review and are not cached. Listening sockets and remote addresses alone are not malicious activity. UDP, packet contents, rule-match attribution and ransomware behavior are outside this view."));
    }
    private void DecisionSettingsCard()
    {
        var body = AdvancedCard("Jev firewall review connection");
        body.IsEnabled = !IsAdmin;
        if (IsAdmin) body.Children.Add(Text("Open a standard user session to configure Jev.", 13, true));
        if (decisionSetupError is not null) body.Children.Add(Note(decisionSetupError, "Warning"));
        body.Children.Add(Text("Optional on-demand firewall priority classification, separate from the chat advisor. This connection uses your TypeSafe or Vercel Gateway API key. No account/subscription credentials are imported."));
        var provider = new ComboBox { ItemsSource = Enum.GetValues<DecisionProvider>(), SelectedItem = decisionSettings.Provider, MinWidth = 260, HorizontalAlignment = HorizontalAlignment.Left };
        var endpoint = new TextBox { Text = decisionSettings.Endpoint, MaxLength = 2048 };
        var model = new TextBox { Text = decisionSettings.Model, MaxLength = 256 };
        var password = new PasswordBox { Password = decisionKey, MaxLength = 8192 };
        Named(provider, "Jev decision provider"); Named(endpoint, "Jev API endpoint"); Named(model, "Jev model ID"); Named(password, "Jev API key");
        body.Children.Add(FieldLabel("Decision provider")); body.Children.Add(provider);
        body.Children.Add(FieldLabel("Base endpoint (TypeSafe-compatible HTTP API)")); body.Children.Add(endpoint);
        body.Children.Add(FieldLabel("Decision model ID")); body.Children.Add(model);
        body.Children.Add(FieldLabel("Separate API key (settings and key encrypted together for this Windows user)")); body.Children.Add(password);
        provider.SelectionChanged += (_, _) => {
            var preset = DecisionSettings.Preset((DecisionProvider)provider.SelectedItem);
            endpoint.Text = preset.Endpoint; model.Text = preset.Model; password.Password = "";
            StatusText = "Decision provider changed. Its preset is selected; enter the key for that provider.";
        };
        body.Children.Add(Row(Button("Save Jev connection", () => {
            if (IsAdmin) { StatusText = "Use a standard user session to configure Jev."; return; }
            try {
                var next = new DecisionSettings((DecisionProvider)provider.SelectedItem, endpoint.Text.Trim(), model.Text.Trim());
                LocalStore.SaveDecision(next, password.Password); decisionSettings = next; decisionKey = password.Password;
                decisionSetupError = null; decisionReviews = null;
                StatusText = "Jev connection saved. Open Firewall, refresh local evidence and opt in to a selected review.";
            } catch (Exception ex) { StatusText = ex.Message; }
        }, true)));
        body.Children.Add(Note("Native HTTP client, five-second deadline, no automatic retries, 64 KiB response limit, strict typed probabilities and no model tools. The Vercel preset uses its TypeSafe-compatible endpoint. Live API behavior and classification quality require your own opt-in evaluation; live Jev inference has not been tested during development."));
    }
}
