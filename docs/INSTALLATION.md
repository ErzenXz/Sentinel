# Installation and removal

Download the setup executable from the [v0.12 release](https://github.com/ErzenXz/Sentinel/releases/tag/v0.12.0), choosing `win-x64` for Intel/AMD Windows or `win-arm64` for Windows ARM64. Windows 10 build 19041 or newer is required; use a supported Windows version. The application and scanner payloads are native to their target architecture. Inno's setup engine is x86 and runs through Windows compatibility on both targets.

Setup installs into the current user's `%LOCALAPPDATA%\Programs\Sentinel`, adds a Start-menu entry and registers with Windows Settings → Apps → Installed apps. It requests no administrator privileges. A desktop shortcut is optional and off by default. Open Sentinel from Start after setup finishes. Setup creates no login startup entry, Windows service, automatic scan, AI connection or firewall change. Monitoring, tray persistence and automatic feed checks retain their existing opt-in preferences.

These previews are unsigned. Windows may display publisher/SmartScreen warnings; signing remains release work. Compare the downloaded file's SHA-256 with the release's `SHA256SUMS` manifest using `Get-FileHash`. A checksum establishes agreement with the published file, not independent trust in the publisher. Keep Microsoft Defender enabled.

## Repair and upgrade

Exit Sentinel, including its tray icon, and wait for command-line/scheduled scans to finish before running setup. A process-held marker blocks setup and uninstall while the current user's app or scanner is active; a transition marker prevents new startup during changes. These guards span Windows sessions and use a UTF-8 profile-path hash. They coordinate cooperative Sentinel processes and do not provide tamper resistance. Legacy v0.11 window coordination is included for the same session; older command-line scanners do not hold the new marker.

Running the same setup again repairs recorded payload files. A later version upgrades the same installation. Setup blocks a downgrade when Windows' recorded version is newer; a malformed recorded version asks you to remove and reinstall. Local settings, history, encrypted credentials and quarantine live separately under `%LOCALAPPDATA%\Sentinel` and are preserved. Do not install over a running older portable scanner. Architecture selection is enforced by setup; the x64 package is not offered as the ARM64 installation.

## Remove

Use Windows Settings → Apps → Installed apps → Sentinel → Uninstall. Exit the app/scanner first. The uninstaller removes recorded program files, shortcuts and its Windows uninstall entry. It preserves untracked files in the program directory, local profile/history, DPAPI credentials and quarantine. Existing Windows Firewall blocks remain in place; review and remove them deliberately from Sentinel or Windows Firewall before uninstalling if desired.

Only the current user's `Sentinel-OwnScan-<SID>` task with Sentinel's exact description and a single executable action pointing to this installation's scanner is removed. Tasks pointing to another portable/installed copy or carrying a different description are preserved. If this matching task cannot be queried or removed, uninstall stops before deleting program files and asks you to review Task Scheduler and retry. This cleanup uses Windows PowerShell and Task Scheduler; neither Node nor Sentinel's runtime is required by the uninstaller.

Reinstall can reuse the preserved local profile and decrypt its credentials for the same Windows user. Quarantine recovery still needs its original DPAPI-protected key; deleting the entire profile or transferring it to another Windows account can prevent recovery. Restore desired files deliberately before deleting local data.

## Build verification

`scripts/build-installer.ps1` pins Inno Setup 7.1.0, checks the official compiler-installer SHA-256 and valid publisher Authenticode signature before executing it, and checks the installed compiler's version/signature. The generated payload manifest covers every included file with relative path, length and SHA-256. Source distribution includes the installer source and cleanup script. See [toolchain pin](../scripts/installer-toolchain.json) and [official verification guidance](https://jrsoftware.org/isdl-verify.php).

Hosted Windows CI creates a disposable standard account with a Unicode profile. It checks installation, all installed payload digests, native architecture, shortcuts, current-user registry entries, offline scan/history, DPAPI preservation, running-app/startup guards, repair, version transitions, task ownership, cleanup failure, removal/reinstall and untracked-file preservation. This harness refuses to create accounts outside a disposable GitHub-hosted runner. Native UI jobs also require the actual process architecture to match x64/ARM64. These checks do not establish hardware compatibility, code-signing trust, standalone antivirus protection or overall memory savings.
