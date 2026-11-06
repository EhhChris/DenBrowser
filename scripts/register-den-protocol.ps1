<#
.SYNOPSIS
    Register or remove the den: URL scheme for DenBrowser on Windows.

.DESCRIPTION
    Writes SOFTWARE\Classes\den so that den:https://... links opened from other
    applications start DenBrowser at the wrapped URL. Machine scope (HKLM, the
    default) needs an elevated shell and is the deployment target; User scope
    (HKCU) is for testing. Per-user registrations take precedence over the
    machine-wide one.

    The registered command is the only launch form DenBrowser accepts:
        "<denbrowser.exe>" -osint -url "%1"
    Patch 015 unwraps den:<url> or den://<url> to the http(s) URL it carries and
    rejects anything else, so this script does no URL handling of its own.

    An existing den registration in the chosen scope is replaced, not merged.
    A registration that does not point at a denbrowser.exe is left alone unless
    -Force is given.

    Uses only registry provider cmdlets, so it also runs under PowerShell
    Constrained Language Mode (for example on WDAC-enforced machines).

.PARAMETER BrowserPath
    Path to the installed denbrowser.exe. Relative paths resolve against the
    current PowerShell location.

.PARAMETER Scope
    Machine (HKLM, default) or User (HKCU).

.PARAMETER Unregister
    Remove the den registration from the chosen scope. Run this when
    uninstalling DenBrowser.

.PARAMETER Force
    Replace or remove a den registration that points at another program.

.EXAMPLE
    .\register-den-protocol.ps1 -BrowserPath 'C:\Program Files\DenBrowser\denbrowser.exe'

.EXAMPLE
    .\register-den-protocol.ps1 -Scope User -BrowserPath .\denbrowser.exe -WhatIf

.EXAMPLE
    .\register-den-protocol.ps1 -Unregister
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BrowserPath,

    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'Machine',

    [switch]$Unregister,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Scope -eq 'Machine') {
    $key = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\den'
    $label = 'HKLM\SOFTWARE\Classes\den'
} else {
    if ((whoami /user /fo csv /nh) -match '"S-1-5-18"') {
        throw '-Scope User under the SYSTEM account registers den: for no real user. Use -Scope Machine.'
    }
    $key = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Classes\den'
    $label = 'HKCU\SOFTWARE\Classes\den'
}

if ($Scope -eq 'Machine' -and (Test-Path -LiteralPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Classes\den')) {
    Write-Warning ('HKCU\SOFTWARE\Classes\den exists for {0} and overrides the machine-wide registration for that user. Remove it with -Scope User -Unregister.' -f $env:USERNAME)
}

if (Test-Path -LiteralPath $key) {
    $existing = $null
    $commandValue = Get-ItemProperty -LiteralPath "$key\shell\open\command" -Name '(default)' -ErrorAction SilentlyContinue
    if ($commandValue) {
        $existing = $commandValue.'(default)'
    }
    if (-not $Force -and -not ($existing -and $existing -match 'denbrowser\.exe"? ')) {
        $shown = if ($existing) { $existing } else { '<none>' }
        throw ('{0} exists and does not point at denbrowser.exe (command: {1}). Pass -Force to replace or remove it.' -f $label, $shown)
    }
    if ($existing) {
        Write-Host "Existing $label command: $existing"
    }
}

if ($Unregister) {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse
        if (-not $WhatIfPreference) { Write-Host "Removed $label" }
    } else {
        Write-Host "$label is not registered"
    }
    return
}

if (-not $BrowserPath) {
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $BrowserPath = Join-Path $programFiles 'DenBrowser\denbrowser.exe'
}
if (-not (Test-Path -LiteralPath $BrowserPath -PathType Leaf)) {
    throw "denbrowser.exe not found at '$BrowserPath'. Pass -BrowserPath."
}
$BrowserPath = Convert-Path -LiteralPath $BrowserPath
$command = '"{0}" -osint -url "%1"' -f $BrowserPath

if ($WhatIfPreference) {
    Write-Host "What if: write $label"
    Write-Host "  (Default)                     URL:DenBrowser Link"
    Write-Host "  URL Protocol                  (empty)"
    Write-Host "  DefaultIcon\(Default)         $BrowserPath,0"
    Write-Host "  shell\open\command\(Default)  $command"
    return
}

try {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse
    }
    New-Item -Path $key -Value 'URL:DenBrowser Link' -Force | Out-Null
    New-ItemProperty -LiteralPath $key -Name 'URL Protocol' -Value '' -PropertyType String | Out-Null
    New-Item -Path "$key\DefaultIcon" -Value "$BrowserPath,0" -Force | Out-Null
    New-Item -Path "$key\shell\open\command" -Value $command -Force | Out-Null
} catch [System.Security.SecurityException], [System.UnauthorizedAccessException] {
    throw "Writing $label was denied. Machine scope needs an elevated shell; use -Scope User for a per-user registration."
}

if (-not $WhatIfPreference) {
    Write-Host "Registered $label"
    Write-Host "  command: $command"
}
