[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string] $InstallRoot,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x86', 'x64')]
    [string] $Architecture,

    [Parameter(Mandatory = $true)]
    [switch] $RegistrationRemoved,

    [switch] $AllowModifiedBinary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RegistrationRemoved) {
    throw 'Remove the Citrix module registration with the matching deployment package first, then pass -RegistrationRemoved.'
}

$root = [System.IO.Path]::GetFullPath($InstallRoot)
$destinationDirectory = Join-Path $root (Join-Path 'DENCAP' $Architecture)
$destination = Join-Path $destinationDirectory 'dencap_vd.dll'
$manifestPath = Join-Path $destinationDirectory 'install-manifest.json'

if (-not (Test-Path -LiteralPath $destination) -and
    -not (Test-Path -LiteralPath $manifestPath)) {
    Write-Output "No DENCAP $Architecture installation found at $destinationDirectory"
    return
}

$resolvedRoot = [System.IO.Path]::GetFullPath($root).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$resolvedDirectory = [System.IO.Path]::GetFullPath($destinationDirectory)
if (-not $resolvedDirectory.StartsWith(
    $resolvedRoot + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Refusing unexpected destination: $resolvedDirectory"
}

foreach ($directory in @(
    $root,
    (Join-Path $root 'DENCAP'),
    $destinationDirectory
)) {
    if (Test-Path -LiteralPath $directory -PathType Container) {
        $item = Get-Item -LiteralPath $directory -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to uninstall through a reparse point: $directory"
        }
    }
}
foreach ($file in @($destination, $manifestPath)) {
    if (Test-Path -LiteralPath $file -PathType Leaf) {
        $item = Get-Item -LiteralPath $file -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to uninstall a reparse point: $file"
        }
    }
}

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Install manifest is missing; refusing to delete $destination"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.architecture -ne $Architecture) {
    throw 'Install manifest schema or architecture does not match.'
}
$manifestDestination = [System.IO.Path]::GetFullPath([string]$manifest.destination)
if (-not $manifestDestination.Equals(
    [System.IO.Path]::GetFullPath($destination),
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Install manifest destination does not match: $manifestDestination"
}
if (Test-Path -LiteralPath $destination -PathType Leaf) {
    $actualHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($actualHash -ne [string]$manifest.sha256 -and -not $AllowModifiedBinary) {
        throw 'Installed DLL differs from its manifest. Investigate or explicitly pass -AllowModifiedBinary.'
    }
}

foreach ($file in @($destination, $manifestPath)) {
    if ((Test-Path -LiteralPath $file -PathType Leaf) -and
        $PSCmdlet.ShouldProcess($file, 'remove DENCAP client file')) {
        Remove-Item -LiteralPath $file -Force
    }
}

if ((Test-Path -LiteralPath $destinationDirectory -PathType Container) -and
    -not (Get-ChildItem -LiteralPath $destinationDirectory -Force) -and
    $PSCmdlet.ShouldProcess($destinationDirectory, 'remove empty DENCAP architecture directory')) {
    Remove-Item -LiteralPath $destinationDirectory
}

Write-Warning 'This script intentionally does not edit Citrix registry/configuration storage.'
