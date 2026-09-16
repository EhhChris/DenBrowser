#requires -Version 5.1
<#
.SYNOPSIS
Installs and registers DENCAP in a per-machine Citrix Workspace installation.
.EXAMPLE
.\deploy\Install-DenCapClient.ps1 -AllowUnsignedDevelopmentBuild
.NOTES
Run elevated after closing all Citrix sessions. PackageRoot contains bin/x86 and bin/x64.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string] $PackageRoot = (Split-Path -Parent $PSScriptRoot),
    [string] $WorkspacePath,
    [switch] $AllowUnsignedDevelopmentBuild
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DenCap.Deployment.ps1')
Install-DenCapClient @PSBoundParameters -DefaultPackageRoot $PackageRoot
