param([ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $root "artifacts/portable/$Runtime-$([Guid]::NewGuid().ToString('N'))"
dotnet run --project (Join-Path $root 'tests/Sentinel.Tests') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }
dotnet publish (Join-Path $root 'src/Sentinel.App') -c Release -r $Runtime --self-contained true -o $output -p:PublishReadyToRun=false
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
dotnet publish (Join-Path $root 'src/Sentinel.Cli') -c Release -r $Runtime --self-contained true -o $output -p:PublishReadyToRun=false
if ($LASTEXITCODE -ne 0) { throw 'Scanner publish failed.' }
Copy-Item (Join-Path $root 'LICENSE') $output
Copy-Item (Join-Path $root 'README.md') $output
Copy-Item (Join-Path $root 'docs') $output -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $output 'server') | Out-Null
foreach ($item in @('package.json','*.mjs','Dockerfile','compose.yml','README.md','.dockerignore')) { Copy-Item (Join-Path $root "server/$item") (Join-Path $output 'server') }
Copy-Item (Join-Path $root 'server/test') (Join-Path $output 'server') -Recurse -Force
Copy-Item (Join-Path $root 'server/seeds') (Join-Path $output 'server') -Recurse -Force
$project = [xml](Get-Content -LiteralPath (Join-Path $root 'src/Sentinel.App/Sentinel.App.csproj') -Raw)
$version = [string]$project.Project.PropertyGroup.Version
$archive = Join-Path $root "artifacts/Sentinel-$version-$Runtime.zip"
Compress-Archive -Path (Join-Path $output '*') -DestinationPath $archive -Force
Get-FileHash $archive -Algorithm SHA256
Remove-Item -LiteralPath $output -Recurse -Force
