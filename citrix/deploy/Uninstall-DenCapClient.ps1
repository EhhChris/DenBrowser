#requires -Version 5.1
<#
.SYNOPSIS
Removes only the DENCAP registration and files owned by this installer.
.EXAMPLE
.\deploy\Uninstall-DenCapClient.ps1
.NOTES
Run elevated after closing all Citrix sessions. Other virtual channels are preserved.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([string] $WorkspacePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DenCap.Deployment.ps1')
Uninstall-DenCapClient @PSBoundParameters
