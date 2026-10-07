param(
    [Parameter(Mandatory)][ValidateSet('win-x64','win-arm64')][string]$Runtime,
    [Parameter(Mandatory)][string]$PayloadDirectory,
    [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -and $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Build the installer on Windows.' }
if ($Version -notmatch '^0\.\d+\.\d+$') { throw 'Invalid installer version.' }
$root = Split-Path $PSScriptRoot -Parent
$payload = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$artifacts = Join-Path $root 'artifacts'
$toolchain = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'installer-toolchain.json') -Raw | ConvertFrom-Json
$tools = Join-Path $artifacts "inno-$($toolchain.version)"
$compiler = Join-Path $tools 'ISCC.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $download = Join-Path $artifacts "innosetup-$($toolchain.version)-x64.exe"
    Invoke-WebRequest -Uri $toolchain.url -OutFile $download
    if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $toolchain.sha256) { throw 'Compiler download digest mismatch.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $download
    $publisher = [regex]::Escape($toolchain.publisher)
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch "(^|,\s*)CN=$publisher(,|$)") { throw 'Compiler Authenticode verification failed.' }
    $process = Start-Process -FilePath $download -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER',"/DIR=`"$tools`"") -Wait -PassThru
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $compiler)) { throw 'Verified compiler installation failed.' }
}
$compilerSignature = Get-AuthenticodeSignature -LiteralPath $compiler
$publisher = [regex]::Escape($toolchain.publisher)
if ($compilerSignature.Status -ne 'Valid' -or $compilerSignature.SignerCertificate.Subject -notmatch "(^|,\s*)CN=$publisher(,|$)") { throw 'Installed compiler Authenticode verification failed.' }
# ISCC's executable resource version differs from the actual compiler engine.
$compilerVersion = (& $compiler --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $compilerVersion -ne $toolchain.version) { throw "Pinned compiler engine version mismatch: $compilerVersion" }
foreach ($assembly in @('Sentinel','Sentinel.Scanner')) {
    $runtimeOptions = (Get-Content -LiteralPath (Join-Path $payload "$assembly.runtimeconfig.json") -Raw | ConvertFrom-Json).runtimeOptions
    if ($runtimeOptions.configProperties.'System.IO.Compression.UseStrictValidation' -ne $true -or $null -eq $runtimeOptions.includedFrameworks) { throw 'Invalid packaged runtime.' }
    if (-not (Test-Path -LiteralPath (Join-Path $payload "$assembly.exe"))) { throw 'Missing packaged executable.' }
}
$manifestPath = Join-Path $payload 'installed-files.json'
$files = @(Get-ChildItem -LiteralPath $payload -File -Recurse | Where-Object { $_.FullName -ne $manifestPath } | Sort-Object FullName | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($payload.Length + 1).Replace('\','/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
if ($files.Count -gt 2000) { throw 'Installer payload file budget exceeded.' }
[ordered]@{ schemaVersion = 1; version = $Version; runtime = $Runtime; files = $files } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$auxiliary = Join-Path $artifacts "installer-aux-$Runtime"
New-Item -ItemType Directory -Path $auxiliary -Force | Out-Null
$lines = [IO.File]::ReadAllLines((Join-Path $PSScriptRoot 'cleanup-user-task.ps1'))
$quoted = @($lines | ForEach-Object { "  '" + $_.Replace("'", "''") + "' + #13#10" })
$cleanupCode = "const CleanupPowerShell =`r`n" + ($quoted -join " +`r`n") + ";`r`n"
[IO.File]::WriteAllText((Join-Path $auxiliary 'CleanupScript.iss'), $cleanupCode, [Text.UTF8Encoding]::new($false))
& $compiler --quiet --messages-jsonl "/DAppVersion=$Version" "/DRuntime=$Runtime" "/DPayloadDirectory=$payload" "/DAuxiliaryDirectory=$auxiliary" "/DOutputDirectory=$artifacts" (Join-Path $root 'installer/Sentinel.iss')
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }
$setup = Join-Path $artifacts "Sentinel-$Version-$Runtime-setup.exe"
if (-not (Test-Path -LiteralPath $setup)) { throw 'Compiled installer is missing.' }
Get-FileHash -LiteralPath $setup -Algorithm SHA256
