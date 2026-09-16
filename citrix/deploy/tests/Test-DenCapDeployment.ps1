#requires -Version 5.1
# No Citrix installation, administrator rights, Pester, or real registry writes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'DenCap.Deployment.ps1')
$script:checks = 0
function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -cne $Expected) { throw "$Label : expected [$Expected], got [$Actual]" }
    $script:checks++
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action | Out-Null } catch {
        if ("$_" -notlike "*$Pattern*") { throw "Expected error containing [$Pattern], got: $_" }
        $script:checks++
        return
    }
    throw "Expected error containing [$Pattern]"
}
$script:registry = @{}
$script:writeCount = 0
$script:running = $false
$script:failName = ''
function Get-DenCapRegistryState([string]$View, [string]$Path) {
    $key = "$View/$Path"
    if (-not $script:registry.ContainsKey($key)) { return [pscustomobject]@{ Exists = $false; Values = @{}; Subkeys = @() } }
    $values = @{}
    foreach ($name in $script:registry[$key].Keys) {
        $entry = $script:registry[$key][$name]
        $values[$name] = [pscustomobject]@{ Kind = $entry.Kind; Data = $entry.Data }
    }
    return [pscustomobject]@{ Exists = $true; Values = $values; Subkeys = @() }
}
function Set-DenCapRegistryValue([string]$View, [string]$Path, [string]$Name, $Value) {
    if ($script:failName -eq $Name) { $script:failName = ''; throw 'injected registry failure' }
    $script:writeCount++
    $key = "$View/$Path"
    if (-not $script:registry.ContainsKey($key)) {
        if ($null -eq $Value) { return }
        $script:registry[$key] = @{}
    }
    if ($null -eq $Value) { $script:registry[$key].Remove($Name) }
    else { $script:registry[$key][$Name] = $Value }
}
function Remove-DenCapEmptyRegistryKey([string]$View, [string]$Path) {
    $key = "$View/$Path"
    if ($script:registry.ContainsKey($key) -and $script:registry[$key].Count -eq 0) { $script:registry.Remove($key) }
}
function Get-Process { param($Name, $ErrorAction) if ($script:running) { [pscustomobject]@{ Id = 42 } } }
function Assert-DenCapAdministrator {}
function Get-AuthenticodeSignature { param($LiteralPath) [pscustomobject]@{ Status = 'NotSigned' } }
function Write-TestPe([string]$Path, [UInt16]$Machine, [byte]$Marker = 0) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $bytes = New-Object byte[] 256
    $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[0x3c] = 0x80
    $bytes[0x80] = 0x50; $bytes[0x81] = 0x45
    [BitConverter]::GetBytes($Machine).CopyTo($bytes, 0x84)
    $bytes[255] = $Marker
    [IO.File]::WriteAllBytes($Path, $bytes)
}
function Set-TestValue([string]$View, [string]$Path, [string]$Name, $Data, [string]$Kind = 'String') {
    Set-DenCapRegistryValue $View $Path $Name ([pscustomobject]@{ Kind = $Kind; Data = $Data })
}
function Set-TestRuntime([string]$Architecture, [int]$Build = 36247) {
    $path = "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Architecture"
    foreach ($pair in @(@('Installed', 1), @('Major', 14), @('Minor', 51), @('Bld', $Build), @('Rbld', 0))) {
        Set-TestValue Registry32 $path $pair[0] $pair[1] DWord
    }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('dencap-deploy-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    Assert-Equal (Update-DenCapDriverList 'Alpha, Beta ' Add) 'Alpha, Beta ,DENCAP' 'append preserves exact other text'
    Assert-Equal (Update-DenCapDriverList 'Alpha, dEnCaP ,Beta' Add) 'Alpha, dEnCaP ,Beta' 'add is case insensitive and idempotent'
    Assert-Equal (Update-DenCapDriverList 'Alpha,DENCAP,Beta,DENCAP2' Remove) 'Alpha,Beta,DENCAP2' 'remove exact tokens only'
    Assert-Equal (Update-DenCapDriverList '' Add) 'DENCAP' 'empty list'
    foreach ($architecture in @('x86', 'x64')) {
        $script:registry = @{}
        $view = if ($architecture -eq 'x86') { 'Registry32' } else { 'Registry64' }
        $machine = if ($architecture -eq 'x86') { 0x014c } else { 0x8664 }
        $root = Join-Path $testRoot $architecture
        $workspacePath = Join-Path $root 'ICA Client'
        $package = Join-Path $root 'package'
        $dll = Join-Path $package "bin\$architecture\dencap_vd.dll"
        Write-TestPe (Join-Path $workspacePath 'wfica32.exe') $machine
        Write-TestPe $dll $machine
        @{ schema = 1; version = '14.51.36247.0' } | ConvertTo-Json | Set-Content (Join-Path $package "bin\$architecture\runtime-requirement.json")
        Set-TestValue $view 'SOFTWARE\Citrix\Install\ICA Client' InstallFolder $workspacePath
        $icaPath = "$script:DenCapModules\ICA 3.0"
        Set-TestValue $view $icaPath VirtualDriverEx 'Alpha, Beta '
        $workspace = Get-DenCapWorkspace
        Assert-Equal $workspace.Root $workspacePath "$architecture path discovery"
        Assert-Equal $workspace.RegistryView $view "$architecture registry view"
        Assert-Equal (Get-DenCapPeArchitecture $dll) $architecture "$architecture PE detection"

        Assert-Throws { Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath } 'signature'
        Set-TestRuntime $architecture 1
        Assert-Throws { Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild } 'runtime'
        Set-TestRuntime $architecture
        $script:running = $true
        Assert-Throws { Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild } 'Close all Citrix'
        $script:running = $false
        $writes = $script:writeCount
        Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild -WhatIf
        Assert-Equal $script:writeCount $writes "$architecture WhatIf registry untouched"
        Assert-Equal (Test-Path $workspace.StateDirectory) $false "$architecture WhatIf filesystem untouched"

        # A registration owned by another installer must not be appropriated.
        Set-TestValue $view $workspace.ModulePath DriverNameWin32 'other.dll'
        Assert-Throws { Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild } 'without our matching manifest'
        $script:registry.Remove("$view/$($workspace.ModulePath)")
        Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild | Out-Null
        Assert-Equal (Get-DenCapDriverList (Get-DenCapRegistryState $view $icaPath)) 'Alpha, Beta ,DENCAP' "$architecture registration"
        Assert-Equal (Test-Path $workspace.ManifestPath) $true "$architecture ownership manifest"
        Assert-Equal (Test-Path $workspace.JournalPath) $false "$architecture completed journal removed"
        $writes = $script:writeCount
        Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild | Out-Null
        Assert-Equal $script:writeCount $writes "$architecture repeated install no writes"

        # Failed replacement restores prior DLL, manifest, and exact driver list.
        $oldHash = (Get-FileHash $workspace.DllPath).Hash
        $oldManifest = Get-Content $workspace.ManifestPath -Raw
        Write-TestPe $dll $machine 1
        $script:failName = 'VirtualDriverEx'
        Assert-Throws { Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild } 'prior state was restored'
        Assert-Equal (Get-FileHash $workspace.DllPath).Hash $oldHash "$architecture rollback binary"
        Assert-Equal (Get-Content $workspace.ManifestPath -Raw) $oldManifest "$architecture rollback manifest"
        Assert-Equal (Get-DenCapDriverList (Get-DenCapRegistryState $view $icaPath)) 'Alpha, Beta ,DENCAP' "$architecture rollback list"
        Assert-Equal (Test-Path $workspace.JournalPath) $false "$architecture successful rollback clears journal"
        Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild | Out-Null
        Assert-Equal (Get-FileHash $workspace.DllPath).Hash (Get-FileHash $dll).Hash "$architecture successful upgrade"

        # External mutation of owned settings blocks uninstall.
        Set-TestValue $view $workspace.ModulePath DriverNameWin32 'foreign.dll'
        Assert-Throws { Uninstall-DenCapClient -WorkspacePath $workspacePath } 'modified externally'
        Set-TestValue $view $workspace.ModulePath DriverNameWin32 'dencap_vd.dll'
        Set-TestValue $view $icaPath VirtualDriverEx 'Alpha, Beta ,DENCAP,Later'
        $writes = $script:writeCount
        Uninstall-DenCapClient -WorkspacePath $workspacePath -WhatIf
        Assert-Equal $script:writeCount $writes "$architecture uninstall WhatIf"
        Assert-Equal (Test-Path $workspace.DllPath) $true "$architecture uninstall WhatIf file"
        Uninstall-DenCapClient -WorkspacePath $workspacePath | Out-Null
        Assert-Equal (Get-DenCapDriverList (Get-DenCapRegistryState $view $icaPath)) 'Alpha, Beta ,Later' "$architecture preserve channels added later"
        Assert-Equal (Test-Path $workspace.DllPath) $false "$architecture uninstall binary"
        Assert-Equal (Get-DenCapRegistryState $view $workspace.ModulePath).Exists $false "$architecture uninstall owned key"
        Uninstall-DenCapClient -WorkspacePath $workspacePath | Out-Null

        # A missing initial driver-list value returns to absent, not an empty value.
        $script:registry["$view/$icaPath"].Remove('VirtualDriverEx')
        Install-DenCapClient -PackageRoot $package -WorkspacePath $workspacePath -AllowUnsignedDevelopmentBuild | Out-Null
        Set-TestValue $view $workspace.ModulePath ForeignSetting 'keep'
        Uninstall-DenCapClient -WorkspacePath $workspacePath | Out-Null
        Assert-Equal (Get-DenCapRegistryState $view $icaPath).Values.ContainsKey('VirtualDriverEx') $false "$architecture restore absent list"
        Assert-Equal (Get-DenCapRegistryState $view $workspace.ModulePath).Values['ForeignSetting'].Data 'keep' "$architecture preserve foreign module values"
    }
    Write-Output "PASS: $script:checks deployment checks; fake registry and temporary files only."
} finally {
    # All cleanup stays under this freshly allocated, explicitly checked temp directory.
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'dencap-deploy-tests-*') { throw "Unsafe test cleanup path: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
