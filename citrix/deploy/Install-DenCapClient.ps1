[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $PluginDll,

    [Parameter(Mandatory = $true)]
    [string] $InstallRoot,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x86', 'x64')]
    [string] $Architecture,

    [switch] $AllowUnsignedDevelopmentBuild,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PeArchitecture {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "Not a PE file: $Path"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Invalid PE signature: $Path"
        }
        switch ($reader.ReadUInt16()) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            default { throw "Unsupported PE machine type in $Path" }
        }
    }
    finally {
        $stream.Dispose()
    }
}

$source = (Resolve-Path -LiteralPath $PluginDll).Path
if ([System.IO.Path]::GetExtension($source) -ne '.dll') {
    throw 'PluginDll must be a DLL.'
}

$actualArchitecture = Get-PeArchitecture -Path $source
if ($actualArchitecture -ne $Architecture) {
    throw "DLL is $actualArchitecture but -Architecture is $Architecture."
}

$signature = Get-AuthenticodeSignature -LiteralPath $source
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -and
    -not $AllowUnsignedDevelopmentBuild) {
    throw "Authenticode signature is $($signature.Status). Use a signed production DLL or explicitly pass -AllowUnsignedDevelopmentBuild for a lab."
}

$root = [System.IO.Path]::GetFullPath($InstallRoot)
$destinationDirectory = Join-Path $root (Join-Path 'DENCAP' $Architecture)
$destination = Join-Path $destinationDirectory 'dencap_vd.dll'
$manifestPath = Join-Path $destinationDirectory 'install-manifest.json'

foreach ($directory in @(
    $root,
    (Join-Path $root 'DENCAP'),
    $destinationDirectory
)) {
    if (Test-Path -LiteralPath $directory -PathType Container) {
        $item = Get-Item -LiteralPath $directory -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to install through a reparse point: $directory"
        }
    }
}
if (Test-Path -LiteralPath $destination) {
    $destinationItem = Get-Item -LiteralPath $destination -Force
    if (($destinationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to replace a reparse point: $destination"
    }
}

if ((Test-Path -LiteralPath $destination) -and -not $Force) {
    throw "Destination exists: $destination. Pass -Force to replace this exact file."
}

$action = "copy $Architecture DENCAP client DLL (registry is unchanged)"
if ($PSCmdlet.ShouldProcess($destination, $action)) {
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force:$Force

    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($sourceHash -ne $destinationHash) {
        throw 'Post-copy SHA-256 verification failed.'
    }

    [ordered]@{
        schema = 1
        architecture = $Architecture
        source = $source
        destination = $destination
        sha256 = $destinationHash
        signatureStatus = [string]$signature.Status
        installedUtc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}

Write-Warning 'No Citrix registry/configuration entries were changed. Register the DLL with the matching official VCSDK sample installer/package only after Phase-0 validation.'
Write-Output $destination
