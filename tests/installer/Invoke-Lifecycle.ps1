param([Parameter(Mandatory)][string]$FixtureRoot, [Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$Runtime)
$ErrorActionPreference = 'Stop'
$checks = [Collections.Generic.List[string]]::new()
$timings = [Collections.Generic.List[object]]::new()
$started = [Diagnostics.Stopwatch]::StartNew()
$appProcess = $null
$standardUser = $false
$passed = $false
$failure = $null
$logRoot = Join-Path $FixtureRoot 'logs'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
function Check([bool]$condition, [string]$label) { if (-not $condition) { throw $label }; $checks.Add($label) }
function Execute([string]$file, [string[]]$arguments, [string]$label) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $file -ArgumentList $arguments -PassThru
    if (-not $process.WaitForExit(90000)) { Stop-Process -Id $process.Id -Force; throw "$label exceeded its time limit" }
    $process.Refresh()
    $timings.Add([ordered]@{ operation = $label; milliseconds = $watch.ElapsedMilliseconds; exitCode = $process.ExitCode })
    return $process.ExitCode
}
function Install([string]$label) {
    return Execute (Join-Path $FixtureRoot 'setup.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/LOG=`"$(Join-Path $logRoot "$label.log")`"") $label
}
function Uninstall([string]$label) {
    return Execute (Join-Path $appRoot 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/LOG=`"$(Join-Path $logRoot "$label.log")`"") $label
}
function VerifyPayload {
    $manifest = Get-Content -LiteralPath (Join-Path $appRoot 'installed-files.json') -Raw | ConvertFrom-Json
    Check ($manifest.version -eq $Version -and $manifest.runtime -eq $Runtime) 'Installed manifest matches release version and architecture'
    foreach ($file in $manifest.files) {
        $path = Join-Path $appRoot $file.path
        if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -ne $file.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw 'Installed payload digest mismatch' }
    }
    Check ($manifest.files.Count -gt 100) 'All packaged payload files match their SHA-256 digests'
    foreach ($assembly in @('Sentinel','Sentinel.Scanner')) {
        $options = (Get-Content -LiteralPath (Join-Path $appRoot "$assembly.runtimeconfig.json") -Raw | ConvertFrom-Json).runtimeOptions
        Check ($options.configProperties.'System.IO.Compression.UseStrictValidation' -eq $true -and $null -ne $options.includedFrameworks) "$assembly has its self-contained strict-compression runtime"
    }
    $raw = [IO.File]::ReadAllBytes((Join-Path $appRoot 'Sentinel.exe'))
    $pe = [BitConverter]::ToInt32($raw, 0x3c)
    $expectedMachine = if ($Runtime -eq 'win-arm64') { 0xAA64 } else { 0x8664 }
    Check ([BitConverter]::ToUInt16($raw,$pe + 4) -eq $expectedMachine) 'Installed application executable has the native target architecture'
}
function RegisterFixtureTask([string]$name, [string]$path, [string]$description) {
    $service = New-Object -ComObject 'Schedule.Service'; $service.Connect()
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description = $description
    $definition.Principal.UserId = $identity.User.Value
    $definition.Principal.LogonType = 3 # InteractiveToken
    $definition.Principal.RunLevel = 0 # Least privilege
    $definition.Settings.Enabled = $false # Harmless ownership fixture, never runs.
    $action = $definition.Actions.Create(0); $action.Path = $path; $action.Arguments = '--help'
    $service.GetFolder('\').RegisterTaskDefinition($name, $definition, 6, $identity.User.Value, $null, 3, $null) | Out-Null
}
function TaskExists([string]$name) {
    $service = New-Object -ComObject 'Schedule.Service'; $service.Connect()
    try { $null = $service.GetFolder('\').GetTask($name); return $true }
    catch {
        if ($_.Exception.HResult -eq -2147024894 -or $_.Exception.InnerException.HResult -eq -2147024894) { return $false }
        throw
    }
}
function VerifyPreserved {
    foreach ($entry in $preserved.GetEnumerator()) { Check ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash -eq $entry.Value) 'Local profile bytes survive installation and removal' }
    $unlocked = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyFile), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    Check ([Text.Encoding]::UTF8.GetString($unlocked) -eq 'Sentinel harmless CI credential') 'Current-user DPAPI credential still decrypts after reinstall'
    [Array]::Clear($unlocked, 0, $unlocked.Length)
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $identity.Name.Split('\')[-1] -notmatch '^SnÜ[0-9a-f]{12}$') { throw 'Lifecycle child requires its disposable hosted CI fixture account' }
    $standardUser = -not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check $standardUser 'Installer and uninstaller run as a standard user without UAC'
    # A secondary-logon account has not run the interactive Windows shell yet.
    # Initialize only its own standard known folders, as a first login would.
    $local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData, [Environment+SpecialFolderOption]::Create)
    Check (-not [string]::IsNullOrWhiteSpace($local) -and [IO.Path]::IsPathRooted($local)) 'Windows resolves a fully qualified local user folder'
    foreach ($folder in @([Environment+SpecialFolder]::Programs, [Environment+SpecialFolder]::DesktopDirectory, [Environment+SpecialFolder]::Startup)) {
        $null = [Environment]::GetFolderPath($folder, [Environment+SpecialFolderOption]::Create)
    }
    $appRoot = Join-Path $local 'Programs/Sentinel'
    $profile = Join-Path $local 'Sentinel'
    Check ($local -match 'SnÜ') 'Unicode user profile exercises the cross-language UTF-8 installation guard'
    Check (-not (Test-Path -LiteralPath $appRoot) -and -not (Test-Path -LiteralPath $profile)) 'Fixture begins without an existing install or profile'
    $registryRoot = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
    $registryPath = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{D388A691-58D4-490F-A497-080F2DD66C83}_is1'
    Check ((Install 'first-install') -eq 0) 'First installation succeeds'
    VerifyPayload
    $installed = $registryRoot.OpenSubKey($registryPath)
    Check ($null -ne $installed -and $installed.GetValue('DisplayVersion') -eq $Version) 'Apps and Features entry belongs to the current user'
    Check ($installed.GetValue('InstallLocation').TrimEnd('\') -eq $appRoot.TrimEnd('\')) 'Default install directory is per user'
    $installed.Dispose()
    $shortcut = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)) 'Sentinel/Sentinel.lnk'
    $shell = New-Object -ComObject WScript.Shell
    Check ((Test-Path -LiteralPath $shortcut) -and $shell.CreateShortcut($shortcut).TargetPath -eq (Join-Path $appRoot 'Sentinel.exe')) 'Start-menu shortcut opens the installed application'
    Check (-not (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)) 'Sentinel.lnk'))) 'Desktop shortcut is off by default'
    Check (-not (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)) 'Sentinel.lnk'))) 'Installer adds no login startup shortcut'
    Check (-not (Test-Path -LiteralPath $profile)) 'Installer creates no monitoring, AI or local-profile state'

    New-Item -ItemType Directory -Path $profile -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $profile 'settings.json'), '{}')
    [IO.File]::WriteAllText((Join-Path $profile 'protection-preferences.json'), '{"KeepInTray":false,"NotifyDetections":false,"AutoUpdateFeeds":false,"RememberMonitor":false,"MonitorFolder":""}')
    $keyFile = Join-Path $profile 'provider.dpapi'
    Add-Type -AssemblyName System.Security
    [IO.File]::WriteAllBytes($keyFile, [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes('Sentinel harmless CI credential'), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
    $quarantine = Join-Path $profile 'quarantine'; New-Item -ItemType Directory -Path $quarantine -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $quarantine 'preserve-ci-marker.txt'), 'Preserve local quarantine directory; this is not a malware sample or vault.')
    $benign = Join-Path $FixtureRoot 'benign.txt'; [IO.File]::WriteAllText($benign, 'Harmless installer scan fixture.')
    $scanner = Join-Path $appRoot 'Sentinel.Scanner.exe'
    Check ((Execute $scanner @('scan',"`"$benign`"",'--profile',"`"$profile`"",'--low-impact','--report',"`"$(Join-Path $profile 'scan.json')`"") 'installed-scan') -eq 0) 'Installed command-line scanner checks a benign file and saves history'
    Check (@(Get-ChildItem -LiteralPath (Join-Path $profile 'reports') -File).Count -gt 0) 'Installed scanner history is present'
    $preserved = @{}
    foreach ($file in Get-ChildItem -LiteralPath $profile -File -Recurse) { $preserved[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }

    $sha = [Security.Cryptography.SHA256]::Create()
    $profileKey = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($profile)))).Replace('-','').ToLowerInvariant()
    $setupGuard = [Threading.Mutex]::new($false, ('Global\Sentinel.Setup.v1.' + $profileKey))
    try { Check ((Execute $scanner @('--help') 'startup-during-install') -ne 0) 'Installed scanner refuses new startup while the installation guard is held' }
    finally { $setupGuard.Dispose() }

    $appProcess = Start-Process -FilePath (Join-Path $appRoot 'Sentinel.exe') -PassThru
    $runningName = 'Global\Sentinel.Run.v1.' + $profileKey
    $lease = $null
    for ($attempt=0; $attempt -lt 100; $attempt++) {
        try { $lease = [Threading.Mutex]::OpenExisting($runningName); break } catch [Threading.WaitHandleCannotBeOpenedException] { Start-Sleep -Milliseconds 100 }
    }
    Check ($null -ne $lease -and -not $appProcess.HasExited) 'Installed application starts and holds its Unicode-profile installation guard'
    $lease.Dispose() # Never keep the marker alive in the test after the app exits.
    Check ((Install 'in-use-upgrade') -ne 0) 'Upgrade refuses while Sentinel is running'
    Check ((Uninstall 'in-use-remove') -ne 0) 'Uninstall refuses while Sentinel is running'
    Check (-not $appProcess.HasExited -and (Test-Path -LiteralPath $scanner)) 'In-use guard preserves the running application and its files'
    for ($attempt=0; $attempt -lt 100; $attempt++) {
        $appProcess.Refresh(); if ($appProcess.MainWindowHandle -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 100
    }
    Check ($appProcess.MainWindowHandle -ne [IntPtr]::Zero) 'Installed WPF application displays its window'
    $appProcess.CloseMainWindow() | Out-Null
    Check ($appProcess.WaitForExit(30000)) 'Installed application exits gracefully'
    $appProcess = $null
    VerifyPreserved

    # A local metadata-only provider fixture keeps the real scanner alive while
    # setup/uninstall run. It makes no inference or external network request.
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start(1)
    $scannerProcess = $null; $client = $null
    try {
        $accept = $listener.AcceptTcpClientAsync()
        $port = $listener.LocalEndpoint.Port
        $scannerProcess = Start-Process -FilePath $scanner -ArgumentList @('models','--provider','Ollama','--endpoint',"http://127.0.0.1:$port/") -PassThru -RedirectStandardOutput (Join-Path $logRoot 'scanner-models.json')
        Check ($accept.Wait(10000)) 'Installed scanner reaches the harmless loopback metadata fixture'
        $client = $accept.GetAwaiter().GetResult()
        Check ((Install 'scanner-in-use-upgrade') -ne 0) 'Upgrade refuses while the command-line scanner is running'
        Check ((Uninstall 'scanner-in-use-remove') -ne 0) 'Removal refuses while the command-line scanner is running'
        Check (-not $scannerProcess.HasExited -and (Test-Path -LiteralPath $scanner)) 'Installer leaves the active scanner and files intact'
        $payload = [Text.Encoding]::UTF8.GetBytes('{"models":[]}')
        $header = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($payload.Length)`r`nConnection: close`r`n`r`n")
        $stream = $client.GetStream(); $stream.Write($header,0,$header.Length); $stream.Write($payload,0,$payload.Length); $stream.Flush()
        $client.Dispose(); $client = $null
        Check ($scannerProcess.WaitForExit(10000) -and $scannerProcess.ExitCode -eq 0) 'Installed scanner finishes normally after the guarded metadata request'
    } finally {
        if ($null -ne $client) { $client.Dispose() }; $listener.Stop()
        if ($null -ne $scannerProcess -and -not $scannerProcess.HasExited) { Stop-Process -Id $scannerProcess.Id -Force -ErrorAction SilentlyContinue }
    }

    [IO.File]::WriteAllText((Join-Path $appRoot 'README.md'), 'Repair fixture')
    Check ((Install 'repair') -eq 0) 'Same-version repair succeeds'
    VerifyPayload; VerifyPreserved
    $record = $registryRoot.OpenSubKey($registryPath, $true); $record.SetValue('DisplayVersion','99.0.0'); $record.Dispose()
    Check ((Install 'downgrade') -ne 0) 'Installer blocks a downgrade from a newer recorded version'
    $record = $registryRoot.OpenSubKey($registryPath, $true); $record.SetValue('DisplayVersion','0.11.0'); $record.Dispose()
    Check ((Install 'upgrade') -eq 0) 'Installer accepts an older recorded version and updates it'
    VerifyPayload; VerifyPreserved

    $taskName = 'Sentinel-OwnScan-' + $identity.User.Value
    $unrelated = 'Sentinel-CI-Unrelated-' + $identity.User.Value
    $description = 'Sentinel independent daily folder scan. Runs only for the current logged-in user; no automatic deletion.'
    RegisterFixtureTask $taskName $scanner $description
    RegisterFixtureTask $unrelated $scanner 'Unrelated disabled CI task'
    Check (TaskExists $taskName) 'Standard user can own an interactive limited scheduled task'
    $service = New-Object -ComObject 'Schedule.Service'; $service.Connect()
    $ownedTask = $service.GetFolder('\').GetTask($taskName)
    $originalDacl = $ownedTask.GetSecurityDescriptor(4)
    try {
        $ownedTask.SetSecurityDescriptor(('D:P(D;;SD;;;' + $identity.User.Value + ')(A;;FA;;;' + $identity.User.Value + ')(A;;FA;;;SY)(A;;FA;;;BA)'), 0)
        Check ((Uninstall 'cleanup-denied') -ne 0) 'Task cleanup failure aborts removal'
        Check ((Test-Path -LiteralPath $scanner) -and (Test-Path -LiteralPath $shortcut) -and (TaskExists $taskName)) 'Failed task cleanup preserves program files, shortcut and scan task'
        VerifyPreserved
    } finally { $ownedTask.SetSecurityDescriptor($originalDacl, 0) }
    $unmanaged = Join-Path $appRoot 'preserve-user-file.txt'; [IO.File]::WriteAllText($unmanaged, 'Untracked user file')
    Check ((Uninstall 'remove-owned-task') -eq 0) 'Standard-user uninstall succeeds'
    Check (-not (TaskExists $taskName) -and (TaskExists $unrelated)) 'Uninstaller removes only its own scan task and preserves unrelated tasks'
    Check (-not (Test-Path -LiteralPath $scanner) -and -not (Test-Path -LiteralPath $shortcut)) 'Uninstaller removes recorded program files and Start-menu entry'
    $record = $registryRoot.OpenSubKey($registryPath); Check ($null -eq $record) 'Uninstaller removes its Apps and Features entry'
    Check ((Get-Content -LiteralPath $unmanaged -Raw) -eq 'Untracked user file') 'Uninstaller preserves untracked files in the program directory'
    VerifyPreserved
    Check ((Install 'reinstall') -eq 0) 'Reinstall succeeds with the existing profile'
    VerifyPayload; VerifyPreserved
    RegisterFixtureTask $taskName (Join-Path $FixtureRoot 'another-copy/Sentinel.Scanner.exe') $description
    Check ((Uninstall 'preserve-other-copy') -eq 0) 'Removal succeeds when the scan task belongs to another copy'
    Check (TaskExists $taskName) 'Uninstaller preserves another copy of Sentinel scheduled task'
    VerifyPreserved
    Check ((Install 'reinstall-mismatched-task') -eq 0) 'Reinstall remains possible with another copy scheduled'
    RegisterFixtureTask $taskName $scanner 'Different task description'
    Check ((Uninstall 'preserve-mismatched-task') -eq 0) 'Removal succeeds with a mismatched task description'
    Check (TaskExists $taskName) 'Uninstaller preserves a mismatched task description'
    VerifyPreserved
    $registryRoot.Dispose()
    $passed = $true
} catch {
    # Fixture exceptions contain assertion labels, never credential values.
    $failure = $_.Exception.Message
    Write-Error -Message $failure -ErrorAction Continue
} finally {
    if ($null -ne $appProcess -and -not $appProcess.HasExited) { Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue }
    [ordered]@{ schemaVersion = 1; version = $Version; runtime = $Runtime; standardUser = $standardUser; passed = $passed; checks = @($checks); timings = @($timings); elapsedMilliseconds = $started.ElapsedMilliseconds; failure = $failure } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $FixtureRoot 'verification.json') -Encoding UTF8
}
if (-not $passed) { exit 1 }
exit 0
