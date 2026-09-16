[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ApplicationArchive,
    [string] $ObjectDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\denbrowser-obj'),
    [string] $OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build\dencap')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ApplicationArchive = (Resolve-Path -LiteralPath $ApplicationArchive).Path
$ObjectDirectory = (Resolve-Path -LiteralPath $ObjectDirectory).Path
$overlays = @('mozilla.cfg', 'defaults\pref\autoconfig.js', 'distribution\policies.json')
foreach ($relative in $overlays) {
    if (-not (Test-Path -LiteralPath (Join-Path $ObjectDirectory "dist\bin\$relative") -PathType Leaf)) {
        throw "Build output is missing $relative. Complete the normal build.sh build before packaging."
    }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$package = Join-Path ([IO.Path]::GetFullPath($OutputRoot)) "DenBrowser-VDA-$stamp"
New-Item -ItemType Directory -Path $package -Force | Out-Null
Expand-Archive -LiteralPath $ApplicationArchive -DestinationPath $package
$applications = @(Get-ChildItem -LiteralPath $package -Filter 'denbrowser.exe' -File -Recurse)
if ($applications.Count -ne 1) {
    throw "Expected one denbrowser.exe in the browser archive; found $($applications.Count)."
}
$applicationDirectory = $applications[0].DirectoryName
foreach ($relative in $overlays) {
    $destination = Join-Path $applicationDirectory $relative
    New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $ObjectDirectory "dist\bin\$relative") -Destination $destination
}
$prefix = $package.TrimEnd('\') + '\'
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | ForEach-Object {
    [ordered]@{
        path = $_.FullName.Substring($prefix.Length)
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
})
[ordered]@{
    schema = 1
    packagedUtc = [DateTime]::UtcNow.ToString('o')
    sourceArchiveSha256 = (Get-FileHash -LiteralPath $ApplicationArchive -Algorithm SHA256).Hash
    files = $files
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'package-manifest.json') -Encoding UTF8
$archive = "$package.zip"
Compress-Archive -LiteralPath $package -DestinationPath $archive
Write-Output "Browser package: $archive"
Write-Output "Copy the complete application directory to the VDA: $applicationDirectory"
