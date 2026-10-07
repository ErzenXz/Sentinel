param([Parameter(Mandatory)][string]$ExpectedScanner)
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $name = 'Sentinel-OwnScan-' + $identity.User.Value
    # Resolve precisely this user's task, without enumerating other users' tasks.
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    try { $task = $folder.GetTask($name) }
    catch {
        if ($_.Exception.HResult -eq -2147024894 -or $_.Exception.InnerException.HResult -eq -2147024894) { exit 0 }
        throw
    }
    $definition = $task.Definition
    $actions = $definition.Actions
    $description = 'Sentinel independent daily folder scan. Runs only for the current logged-in user; no automatic deletion.'
    if ($definition.RegistrationInfo.Description -ne $description -or $actions.Count -ne 1) { exit 0 }
    $action = $actions.Item(1)
    if ($action.Type -ne 0 -or [string]::IsNullOrWhiteSpace($action.Path)) { exit 0 }
    $expected = [IO.Path]::GetFullPath($ExpectedScanner)
    $actual = [IO.Path]::GetFullPath($action.Path)
    if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) { exit 0 }
    $folder.DeleteTask($name, 0)
    exit 0
} catch {
    # Inno logs a generic failure and stops before removing files; do not echo
    # private paths, task definitions or arbitrary upstream/system error text.
    exit 1
}
