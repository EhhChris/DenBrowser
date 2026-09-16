[CmdletBinding()]
param(
    [ValidateSet('both', 'x86', 'x64')]
    [string] $Architecture = 'both',
    [ValidateSet('Release', 'RelWithDebInfo')]
    [string] $Configuration = 'RelWithDebInfo',
    [string] $SdkRoot = (Join-Path $PSScriptRoot 'VCSDK'),
    [string] $OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build\dencap'),
    [Parameter(DontShow = $true)][switch] $Worker,
    [Parameter(DontShow = $true)][string] $StagingDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$SdkRoot = (Resolve-Path -LiteralPath $SdkRoot).Path
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)

function Invoke-Checked {
    param([string] $Program, [string[]] $Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE."
    }
}

if ($Worker) {
    if ($Architecture -eq 'both' -or -not $StagingDirectory) {
        throw 'A build worker requires one architecture and a staging directory.'
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'Install Visual Studio Build Tools with Desktop development with C++ and CMake tools.'
    }
    $vsPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) { throw 'Visual Studio C++ build tools were not found.' }
    Import-Module (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
    Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments "-arch=$Architecture -host_arch=x64"
    $ninja = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
    $cmake = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    if (-not (Test-Path -LiteralPath $cmake)) {
        $cmake = (Get-Command cmake -ErrorAction Stop).Source
    }
    if (-not (Test-Path -LiteralPath $ninja)) {
        $ninja = (Get-Command ninja -ErrorAction Stop).Source
    }
    $ctest = Join-Path (Split-Path $cmake -Parent) 'ctest.exe'
    $buildDirectory = Join-Path $OutputRoot "$Architecture-$Configuration"
    Invoke-Checked $cmake @('-S', $PSScriptRoot, '-B', $buildDirectory,
        '-G', 'Ninja', "-DCMAKE_MAKE_PROGRAM=$ninja", "-DCMAKE_BUILD_TYPE=$Configuration",
        '-DDENCAP_BUILD_CITRIX_DRIVER=ON', '-DDENCAP_BUILD_TESTS=ON',
        "-DCITRIX_VCSDK_ROOT=$SdkRoot")
    Invoke-Checked $cmake @('--build', $buildDirectory)
    Invoke-Checked $ctest @('--test-dir', $buildDirectory, '--output-on-failure')

    $destination = Join-Path $StagingDirectory "bin\$Architecture"
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($name in @('dencap_vd.dll', 'dencap_hwnd_probe.exe')) {
        Copy-Item -LiteralPath (Join-Path $buildDirectory $name) -Destination $destination
    }
    foreach ($name in @('dencap_vd.pdb', 'dencap_hwnd_probe.pdb')) {
        if (Test-Path -LiteralPath (Join-Path $buildDirectory $name)) {
            Copy-Item -LiteralPath (Join-Path $buildDirectory $name) -Destination $destination
        }
    }
    # Keep diagnostics alongside the binaries; do not execute a runtime installer
    # on the build machine. The demo endpoint may need this matching runtime.
    $runtimeInstaller = Join-Path $env:VCToolsRedistDir "vc_redist.$Architecture.exe"
    if (-not (Test-Path -LiteralPath $runtimeInstaller)) {
        throw "Matching Visual C++ redistributable is missing: $runtimeInstaller"
    }
    $runtimeDirectory = Join-Path $StagingDirectory 'runtime'
    New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
    Copy-Item -LiteralPath $runtimeInstaller -Destination $runtimeDirectory
    $runtimeVersion = (Get-Item -LiteralPath $runtimeInstaller).VersionInfo
    [ordered]@{
        schema = 1
        version = '{0}.{1}.{2}.{3}' -f $runtimeVersion.ProductMajorPart,
            $runtimeVersion.ProductMinorPart, $runtimeVersion.ProductBuildPart,
            $runtimeVersion.ProductPrivatePart
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'runtime-requirement.json') -Encoding UTF8
    $dumpbin = (Get-Command dumpbin -ErrorAction Stop).Source
    & $dumpbin /nologo /exports (Join-Path $destination 'dencap_vd.dll') |
        Set-Content -LiteralPath (Join-Path $destination 'exports.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect DLL exports.' }
    & $dumpbin /nologo /dependents (Join-Path $destination 'dencap_vd.dll') |
        Set-Content -LiteralPath (Join-Path $destination 'dependencies.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect DLL dependencies.' }
    exit 0
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$package = Join-Path $OutputRoot "DENCAP-demo-$stamp"
New-Item -ItemType Directory -Path $package -Force | Out-Null
$shellName = 'powershell.exe'
if ($PSVersionTable.PSEdition -eq 'Core') { $shellName = 'pwsh.exe' }
$shell = Join-Path $PSHOME $shellName
$architectures = @($Architecture)
if ($Architecture -eq 'both') { $architectures = @('x86', 'x64') }

foreach ($target in $architectures) {
    # Separate shells prevent x86 and x64 compiler environment variables from
    # leaking into each other or changing the caller's PowerShell session.
    Invoke-Checked $shell @('-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Worker',
        '-Architecture', $target, '-Configuration', $Configuration,
        '-SdkRoot', $SdkRoot, '-OutputRoot', $OutputRoot,
        '-StagingDirectory', $package)
}

$deployDirectory = Join-Path $package 'deploy'
New-Item -ItemType Directory -Path $deployDirectory -Force | Out-Null
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'deploy') -Filter '*.ps1' |
    Copy-Item -Destination $deployDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'DEMO.md') -Destination (Join-Path $package 'README.md')
$prefix = $package.TrimEnd('\') + '\'
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($prefix.Length); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
[ordered]@{
    schema = 1
    builtUtc = [DateTime]::UtcNow.ToString('o')
    configuration = $Configuration
    architectures = $architectures
    sdkLayout = 'Citrix VCSDK 2507.1'
    files = $files
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'package-manifest.json') -Encoding UTF8
$archive = "$package.zip"
Compress-Archive -LiteralPath $package -DestinationPath $archive
Write-Output "Demo package: $archive"
Write-Output "Unpacked package: $package"
Write-Output 'Read README.md in the package for installation and the live Citrix checks.'
