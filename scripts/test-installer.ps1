param(
    [Parameter(Mandatory)][string]$SetupPath,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidateSet('win-x64','win-arm64')][string]$Runtime
)
$ErrorActionPreference = 'Stop'
# Account/profile creation is restricted to a disposable hosted CI VM. Never run
# these lifecycle tests against a developer's account or installed Sentinel.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Installer lifecycle verification requires a disposable GitHub-hosted Windows runner.' }
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $root "artifacts/installer-verification/$Runtime"
New-Item -ItemType Directory -Path $output -Force | Out-Null
$fixtureRoot = Join-Path $env:ProgramData ('Sentinel-ci-' + [Guid]::NewGuid().ToString('N'))
$fixtureUser = 'SnÜ' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$sid = $null
$process = $null
try {
    $passwordBytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($passwordBytes)
    $password = ([Convert]::ToBase64String($passwordBytes) + 'aA1!') | ConvertTo-SecureString -AsPlainText -Force
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    $account = New-LocalUser -Name $fixtureUser -Password $password -AccountNeverExpires -PasswordNeverExpires -Description 'Disposable Sentinel installer CI fixture'
    $sid = $account.SID.Value
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $acl = Get-Acl -LiteralPath $fixtureRoot
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $fixtureRoot -AclObject $acl
    Copy-Item -LiteralPath (Resolve-Path -LiteralPath $SetupPath).Path -Destination (Join-Path $fixtureRoot 'setup.exe')
    # Windows PowerShell 5.1 needs a BOM to parse the Unicode profile assertion.
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'Invoke-Lifecycle.ps1'), [IO.File]::ReadAllText((Join-Path $root 'tests/installer/Invoke-Lifecycle.ps1')), [Text.UTF8Encoding]::new($true))
    Start-Service -Name 'seclogon'
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$fixtureUser", $password)
    $shell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $fixtureRoot 'Invoke-Lifecycle.ps1')`" -FixtureRoot `"$fixtureRoot`" -Version `"$Version`" -Runtime `"$Runtime`""
    $process = Start-Process -FilePath $shell -ArgumentList $arguments -Credential $credential -LoadUserProfile -PassThru -WorkingDirectory $fixtureRoot -RedirectStandardOutput (Join-Path $fixtureRoot 'stdout.log') -RedirectStandardError (Join-Path $fixtureRoot 'stderr.log')
    if (-not $process.WaitForExit(600000)) { throw 'Installer lifecycle fixture exceeded its ten-minute limit.' }
    $process.Refresh()
    foreach ($file in @('verification.json','stdout.log','stderr.log')) {
        if (Test-Path -LiteralPath (Join-Path $fixtureRoot $file)) { Copy-Item -LiteralPath (Join-Path $fixtureRoot $file) -Destination $output }
    }
    if (Test-Path -LiteralPath (Join-Path $fixtureRoot 'logs')) { Copy-Item -LiteralPath (Join-Path $fixtureRoot 'logs') -Destination $output -Recurse }
    if ($process.ExitCode -ne 0) { throw "Installer lifecycle verification failed; see Installer-$Runtime CI artifact." }
    $report = Get-Content -LiteralPath (Join-Path $output 'verification.json') -Raw | ConvertFrom-Json
    if ($report.passed -ne $true -or $report.standardUser -ne $true -or $report.runtime -ne $Runtime) { throw 'Installer lifecycle receipt validation failed.' }
    Write-Host "PASS $Runtime standard-user installer: $($report.checks.Count) assertions"
} finally {
    if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    if ($null -ne $sid) {
        # Stop only processes owned by this newly created fixture account.
        foreach ($owned in @(Get-CimInstance Win32_Process)) {
            try {
                $owner = Invoke-CimMethod -InputObject $owned -MethodName GetOwnerSid -ErrorAction Stop
                if ($owner.Sid -eq $sid) { Stop-Process -Id $owned.ProcessId -Force -ErrorAction SilentlyContinue }
            } catch { }
        }
        foreach ($taskName in @("Sentinel-OwnScan-$sid", "Sentinel-CI-Unrelated-$sid")) {
            Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        }
        Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Remove-CimInstance -ErrorAction SilentlyContinue
        Remove-LocalUser -Name $fixtureUser -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
