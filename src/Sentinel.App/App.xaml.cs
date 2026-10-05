using System.ComponentModel;
using System.Windows;
namespace Sentinel.App;
public partial class App : System.Windows.Application
{
    private ProfileInstance? instance;
    private bool themeRefreshPending;
    protected override void OnStartup(StartupEventArgs e)
    {
        instance = new ProfileInstance();
        if (!instance.Acquire(e.Args.Contains("--wait-for-profile")))
        {
            if (!ProfileInstance.ActivateExisting()) MessageBox.Show("Sentinel is already running for this user. Open it from the tray, or exit that session before opening another.", "Sentinel already running");
            Shutdown(); return;
        }
        Theme.Apply(); SystemParameters.StaticPropertyChanged += SystemChanged; base.OnStartup(e);
        var window = new MainWindow(); MainWindow = window; window.Show();
    }
    private void SystemChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (themeRefreshPending) return;
        themeRefreshPending = true;
        Dispatcher.BeginInvoke(() => { themeRefreshPending = false; Theme.Apply(); });
    }
    protected override void OnExit(ExitEventArgs e)
    {
        SystemParameters.StaticPropertyChanged -= SystemChanged; instance?.Dispose(); base.OnExit(e);
    }
}
