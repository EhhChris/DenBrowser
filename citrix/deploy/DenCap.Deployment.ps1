# Shared implementation. Dot-sourcing performs no installation.
# Registration: https://developer-docs.citrix.com/en-us/citrix-workspace-app-for-windows/citrix-virtual-channel-sdk-for-citrix-workspace-app-for-windows/using-example-programs.html
Set-StrictMode -Version Latest
$script:DenCapModules = 'SOFTWARE\Citrix\ICA Client\Engine\Configuration\Advanced\Modules'
$script:DenCapFields = [ordered]@{ DriverName = 'Unsupported'; DriverNameWin16 = 'Unsupported'; DriverNameWin32 = 'dencap_vd.dll' }

function Get-DenCapPeArchitecture {
    param([string] $Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { throw "Not a PE file: $Path" }
        $stream.Position = 0x3C
        $offset = $reader.ReadUInt32()
        if ($offset -gt ($stream.Length - 6)) { throw "Invalid PE offset: $Path" }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Path" }
        switch ($reader.ReadUInt16()) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            default { throw "Unsupported PE architecture: $Path. This package supports x86 and x64." }
        }
    } finally { $stream.Dispose() }
}

function Assert-DenCapPlainPath {
    param([string] $Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a reparse point in deployment path: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-DenCapRegistryState {
    param([string] $View, [string] $Path)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::$View)
    try {
        $key = $base.OpenSubKey($Path, $false)
        if (-not $key) { return [pscustomobject]@{ Exists = $false; Values = @{}; Subkeys = @() } }
        try {
            $values = @{}
            foreach ($name in $key.GetValueNames()) {
                $values[$name] = [pscustomobject]@{
                    Kind = [string]$key.GetValueKind($name)
                    Data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                }
            }
            return [pscustomobject]@{ Exists = $true; Values = $values; Subkeys = @($key.GetSubKeyNames()) }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Set-DenCapRegistryValue {
    param([string] $View, [string] $Path, [string] $Name, $Value)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::$View)
    try {
        $key = if ($null -eq $Value) { $base.OpenSubKey($Path, $true) } else { $base.CreateSubKey($Path, $true) }
        if (-not $key) { return }
        try {
            if ($null -eq $Value) { $key.DeleteValue($Name, $false) }
            else { $key.SetValue($Name, $Value.Data, [Microsoft.Win32.RegistryValueKind]::$($Value.Kind)) }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Remove-DenCapEmptyRegistryKey {
    param([string] $View, [string] $Path)
    $state = Get-DenCapRegistryState $View $Path
    if ($state.Exists -and $state.Values.Count -eq 0 -and $state.Subkeys.Count -eq 0) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::$View)
        try { $base.DeleteSubKey($Path, $false) } finally { $base.Dispose() }
    }
}

function Get-DenCapWorkspace {
    param([string] $WorkspacePath)
    $roots = @()
    if ($WorkspacePath) { $roots = @([IO.Path]::GetFullPath($WorkspacePath)) }
    else {
        foreach ($view in @('Registry32', 'Registry64')) {
            if ($view -eq 'Registry64' -and -not [Environment]::Is64BitOperatingSystem) { continue }
            foreach ($keyPath in @('SOFTWARE\Citrix\Install\ICA Client', 'SOFTWARE\Citrix\ICA Client')) {
                $state = Get-DenCapRegistryState $view $keyPath
                foreach ($name in @('InstallFolder', 'InstallDir')) {
                    if ($state.Values.ContainsKey($name) -and $state.Values[$name].Data) {
                        $roots += [Environment]::ExpandEnvironmentVariables([string]$state.Values[$name].Data)
                    }
                }
            }
        }
        foreach ($parent in @([Environment]::GetEnvironmentVariable('ProgramFiles(x86)'), $env:ProgramW6432, $env:ProgramFiles)) {
            if ($parent) { $roots += Join-Path $parent 'Citrix\ICA Client' }
        }
    }
    $candidates = @()
    foreach ($root in @($roots | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') } | Select-Object -Unique)) {
        foreach ($name in @('wfica32.exe', 'wfica64.exe', 'wfica.exe')) {
            $engine = Join-Path $root $name
            if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { continue }
            Assert-DenCapPlainPath $engine
            $architecture = Get-DenCapPeArchitecture $engine
            $view = if ($architecture -eq 'x86') { 'Registry32' } else { 'Registry64' }
            $icaPath = $script:DenCapModules + '\ICA 3.0'
            if (-not (Get-DenCapRegistryState $view $icaPath).Exists) { continue }
            $candidates += [pscustomobject]@{
                Root = $root; Engine = $engine; Architecture = $architecture; RegistryView = $view
                IcaPath = $icaPath; ModulePath = $script:DenCapModules + '\DENCAP'
                DllPath = Join-Path $root 'dencap_vd.dll'
                StateDirectory = Join-Path $root 'DENCAP'
                ManifestPath = Join-Path $root 'DENCAP\install-manifest.json'
                JournalPath = Join-Path $root 'DENCAP\pending-transaction.json'
            }
        }
    }
    if ($candidates.Count -eq 0) {
        throw 'No supported per-machine Workspace engine and matching HKLM ICA 3.0 key found. Use -WorkspacePath with its ICA Client directory. Per-user Workspace installations are not supported.'
    }
    if ($candidates.Count -ne 1) { throw 'Multiple Workspace engines found. Use -WorkspacePath with the ICA Client directory containing the engine to use.' }
    return $candidates[0]
}

function Assert-DenCapNotRunning {
    $clients = @(Get-Process -Name 'wfica32', 'wfica64', 'wfica', 'CDViewer' -ErrorAction SilentlyContinue)
    if ($clients.Count -gt 0) {
        throw ('Close all Citrix sessions and Desktop Viewer windows on this endpoint first. Running process IDs: ' + (($clients | ForEach-Object { $_.Id }) -join ', '))
    }
}

function Assert-DenCapAdministrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell as Administrator to install or remove the per-machine plug-in. -WhatIf can run without elevation.'
    }
}

function Assert-DenCapRuntime {
    param([string] $PackageRoot, [string] $Architecture)
    $requirementPath = Join-Path $PackageRoot "bin\$Architecture\runtime-requirement.json"
    if (-not (Test-Path -LiteralPath $requirementPath -PathType Leaf)) { throw "Package runtime metadata is missing: $requirementPath. Rebuild the endpoint package." }
    $requirement = Get-Content -LiteralPath $requirementPath -Raw | ConvertFrom-Json
    if ($requirement.schema -ne 1) { throw 'Unsupported package runtime metadata.' }
    $minimum = [version]$requirement.version
    $installed = $false
    foreach ($view in @('Registry32', 'Registry64')) {
        if ($view -eq 'Registry64' -and -not [Environment]::Is64BitOperatingSystem) { continue }
        $runtime = Get-DenCapRegistryState $view "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Architecture"
        if ($runtime.Values.ContainsKey('Installed') -and $runtime.Values['Installed'].Data -eq 1) {
            $parts = @()
            foreach ($name in @('Major', 'Minor', 'Bld', 'Rbld')) {
                if (-not $runtime.Values.ContainsKey($name)) { $parts = @(); break }
                $parts += [string]$runtime.Values[$name].Data
            }
            if ($parts.Count -eq 4 -and [version]($parts -join '.') -ge $minimum) { $installed = $true }
        }
    }
    if (-not $installed) {
        $installer = Join-Path ([IO.Path]::GetFullPath($PackageRoot)) "runtime\vc_redist.$Architecture.exe"
        if (Test-Path -LiteralPath $installer -PathType Leaf) {
            throw "Microsoft Visual C++ $Architecture runtime $minimum or later is required. Run: & '$installer' /install /passive /norestart ; then rerun this script."
        }
        throw "Microsoft Visual C++ $Architecture runtime $minimum or later is required. Install it from https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist and rerun this script."
    }
}

function Get-DenCapDriverList {
    param($IcaState)
    if (-not $IcaState.Values.ContainsKey('VirtualDriverEx')) { return '' }
    $value = $IcaState.Values['VirtualDriverEx']
    if ($value.Kind -ne 'String') { throw 'VirtualDriverEx must be REG_SZ; refusing to replace another registry type.' }
    return [string]$value.Data
}

function Update-DenCapDriverList {
    param([AllowEmptyString()][string] $Current, [ValidateSet('Add', 'Remove')][string] $Action)
    $parts = @($Current -split ',')
    if ($Action -eq 'Add') {
        if (@($parts | Where-Object { $_.Trim() -ieq 'DENCAP' }).Count -gt 0) { return $Current }
        if ($Current.Length -eq 0) { return 'DENCAP' }
        return $Current + ',DENCAP'
    }
    return (@($parts | Where-Object { $_.Trim() -ine 'DENCAP' }) -join ',')
}

function Read-DenCapManifest {
    param($Workspace)
    foreach ($path in @($Workspace.DllPath, $Workspace.ManifestPath, $Workspace.JournalPath)) { Assert-DenCapPlainPath $path }
    if (Test-Path -LiteralPath $Workspace.JournalPath) {
        throw "Interrupted transaction needs review: $($Workspace.JournalPath). Recover its saved registry and file state before retrying."
    }
    if (-not (Test-Path -LiteralPath $Workspace.ManifestPath -PathType Leaf)) { return $null }
    $manifest = Get-Content -LiteralPath $Workspace.ManifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 2 -or $manifest.product -ne 'DenBrowser.DENCAP' -or
        $manifest.workspacePath -ine $Workspace.Root -or $manifest.dllPath -ine $Workspace.DllPath -or
        $manifest.architecture -ne $Workspace.Architecture -or $manifest.registryView -ne $Workspace.RegistryView) {
        throw 'DENCAP manifest does not match this Workspace installation.'
    }
    if ((Test-Path -LiteralPath $Workspace.DllPath -PathType Leaf) -and
        (Get-FileHash -LiteralPath $Workspace.DllPath -Algorithm SHA256).Hash -ne $manifest.sha256) {
        throw 'Installed DENCAP DLL differs from its manifest. Refusing to replace or remove an unknown binary.'
    }
    return $manifest
}

function Assert-DenCapRegistration {
    param($Workspace, $Manifest, $IcaState, $ModuleState)
    $list = Get-DenCapDriverList $IcaState
    if (-not $Manifest) {
        if ($ModuleState.Exists -or (Test-Path -LiteralPath $Workspace.DllPath) -or
            @($list -split ',' | Where-Object { $_.Trim() -ieq 'DENCAP' }).Count -gt 0) {
            throw 'DENCAP file or registration exists without our matching manifest. Refusing to overwrite it.'
        }
    } else {
        foreach ($name in $script:DenCapFields.Keys) {
            if ($ModuleState.Values.ContainsKey($name) -and
                ($ModuleState.Values[$name].Kind -ne 'String' -or $ModuleState.Values[$name].Data -ine $script:DenCapFields[$name])) {
                throw "DENCAP registry value $name was modified externally. Refusing to overwrite or remove it."
            }
        }
    }
}

function Write-DenCapJson {
    param([string] $Path, $Value)
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-DenCapTransaction {
    param($Workspace, $IcaBefore, $ModuleBefore, [scriptblock] $Action)
    $dllBefore = if (Test-Path -LiteralPath $Workspace.DllPath) { [IO.File]::ReadAllBytes($Workspace.DllPath) } else { $null }
    $manifestBefore = if (Test-Path -LiteralPath $Workspace.ManifestPath) { [IO.File]::ReadAllBytes($Workspace.ManifestPath) } else { $null }
    New-Item -ItemType Directory -Path $Workspace.StateDirectory -Force | Out-Null
    # Retained on interrupted/failed rollback. Exact prior values and files support recovery.
    $journal = [ordered]@{
        schema = 1; product = 'DenBrowser.DENCAP'; workspacePath = $Workspace.Root
        registryView = $Workspace.RegistryView; icaPath = $Workspace.IcaPath; modulePath = $Workspace.ModulePath
        icaBefore = $IcaBefore; moduleBefore = $ModuleBefore
        dllBeforeBase64 = if ($null -ne $dllBefore) { [Convert]::ToBase64String($dllBefore) } else { $null }
        manifestBeforeBase64 = if ($null -ne $manifestBefore) { [Convert]::ToBase64String($manifestBefore) } else { $null }
    }
    Write-DenCapJson $Workspace.JournalPath $journal
    try { & $Action }
    catch {
        $failure = $_
        try {
            $priorList = if ($IcaBefore.Values.ContainsKey('VirtualDriverEx')) { $IcaBefore.Values['VirtualDriverEx'] } else { $null }
            Set-DenCapRegistryValue $Workspace.RegistryView $Workspace.IcaPath 'VirtualDriverEx' $priorList
            foreach ($name in $script:DenCapFields.Keys) {
                $prior = if ($ModuleBefore.Values.ContainsKey($name)) { $ModuleBefore.Values[$name] } else { $null }
                Set-DenCapRegistryValue $Workspace.RegistryView $Workspace.ModulePath $name $prior
            }
            if (-not $ModuleBefore.Exists) { Remove-DenCapEmptyRegistryKey $Workspace.RegistryView $Workspace.ModulePath }
            if ($null -ne $dllBefore) { [IO.File]::WriteAllBytes($Workspace.DllPath, $dllBefore) }
            elseif (Test-Path -LiteralPath $Workspace.DllPath) { Remove-Item -LiteralPath $Workspace.DllPath -Force }
            if ($null -ne $manifestBefore) { [IO.File]::WriteAllBytes($Workspace.ManifestPath, $manifestBefore) }
            elseif (Test-Path -LiteralPath $Workspace.ManifestPath) { Remove-Item -LiteralPath $Workspace.ManifestPath -Force }
            Remove-Item -LiteralPath $Workspace.JournalPath -Force
        } catch { throw "Deployment failed: $failure. Rollback also failed: $_. Recovery journal: $($Workspace.JournalPath)" }
        throw "Deployment failed and prior state was restored: $failure"
    }
    Remove-Item -LiteralPath $Workspace.JournalPath -Force
}

function Install-DenCapClient {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string] $PackageRoot, [string] $DefaultPackageRoot, [string] $WorkspacePath, [switch] $AllowUnsignedDevelopmentBuild)
    if (-not $PackageRoot) { $PackageRoot = $DefaultPackageRoot }
    $workspace = Get-DenCapWorkspace $WorkspacePath
    $source = Join-Path $PackageRoot ('bin\' + $workspace.Architecture + '\dencap_vd.dll')
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Package DLL missing: $source" }
    if ((Get-DenCapPeArchitecture $source) -ne $workspace.Architecture) { throw 'Package DLL architecture differs from Workspace.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $source
    if ($signature.Status -ne 'Valid' -and -not $AllowUnsignedDevelopmentBuild) {
        throw "DLL signature is $($signature.Status). Supply a signed package or explicitly use -AllowUnsignedDevelopmentBuild for a lab."
    }
    Assert-DenCapRuntime $PackageRoot $workspace.Architecture
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $manifest = Read-DenCapManifest $workspace
    $ica = Get-DenCapRegistryState $workspace.RegistryView $workspace.IcaPath
    $module = Get-DenCapRegistryState $workspace.RegistryView $workspace.ModulePath
    Assert-DenCapRegistration $workspace $manifest $ica $module
    $before = Get-DenCapDriverList $ica
    $after = Update-DenCapDriverList $before Add
    $registrationComplete = $module.Exists
    foreach ($name in $script:DenCapFields.Keys) {
        if (-not $module.Values.ContainsKey($name)) { $registrationComplete = $false }
    }
    if ($manifest -and $manifest.sha256 -eq $sourceHash -and (Test-Path -LiteralPath $workspace.DllPath) -and
        $before -eq $after -and $registrationComplete) {
        Write-Output "DENCAP is already installed and registered ($($workspace.Architecture)): $($workspace.DllPath)"
        return
    }
    Assert-DenCapNotRunning
    if (-not $PSCmdlet.ShouldProcess($workspace.Root, "Install $($workspace.Architecture) DENCAP DLL and register HKLM/$($workspace.RegistryView) virtual channel")) { return }
    Assert-DenCapAdministrator
    Invoke-DenCapTransaction $workspace $ica $module {
        Assert-DenCapNotRunning
        Copy-Item -LiteralPath $source -Destination $workspace.DllPath -Force
        if ((Get-FileHash -LiteralPath $workspace.DllPath -Algorithm SHA256).Hash -ne $sourceHash) { throw 'Post-copy SHA256 verification failed.' }
        foreach ($name in $script:DenCapFields.Keys) {
            Set-DenCapRegistryValue $workspace.RegistryView $workspace.ModulePath $name ([pscustomobject]@{ Kind = 'String'; Data = $script:DenCapFields[$name] })
        }
        Set-DenCapRegistryValue $workspace.RegistryView $workspace.IcaPath 'VirtualDriverEx' ([pscustomobject]@{ Kind = 'String'; Data = $after })
        $registered = Get-DenCapRegistryState $workspace.RegistryView $workspace.ModulePath
        foreach ($name in $script:DenCapFields.Keys) {
            if (-not $registered.Values.ContainsKey($name) -or $registered.Values[$name].Kind -ne 'String' -or
                $registered.Values[$name].Data -cne $script:DenCapFields[$name]) { throw "Registration readback failed for $name." }
        }
        if ((Get-DenCapDriverList (Get-DenCapRegistryState $workspace.RegistryView $workspace.IcaPath)) -cne $after) {
            throw 'VirtualDriverEx readback failed.'
        }
        Write-DenCapJson $workspace.ManifestPath ([ordered]@{
            schema = 2; product = 'DenBrowser.DENCAP'; workspacePath = $workspace.Root; dllPath = $workspace.DllPath
            architecture = $workspace.Architecture; registryView = $workspace.RegistryView; sha256 = $sourceHash
            signatureStatus = [string]$signature.Status; installedUtc = [DateTime]::UtcNow.ToString('o')
            virtualDriverExOriginallyAbsent = if ($manifest) { $manifest.virtualDriverExOriginallyAbsent } else { -not $ica.Values.ContainsKey('VirtualDriverEx') }
        })
    }
    Write-Output "Installed DENCAP ($($workspace.Architecture)): $($workspace.DllPath). Start a new Citrix session to load it."
}

function Uninstall-DenCapClient {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string] $WorkspacePath)
    $workspace = Get-DenCapWorkspace $WorkspacePath
    $manifest = Read-DenCapManifest $workspace
    $ica = Get-DenCapRegistryState $workspace.RegistryView $workspace.IcaPath
    $module = Get-DenCapRegistryState $workspace.RegistryView $workspace.ModulePath
    Assert-DenCapRegistration $workspace $manifest $ica $module
    if (-not $manifest) { Write-Output 'DENCAP is not installed.'; return }
    $after = Update-DenCapDriverList (Get-DenCapDriverList $ica) Remove
    Assert-DenCapNotRunning
    if (-not $PSCmdlet.ShouldProcess($workspace.Root, 'Remove owned DENCAP registration and DLL')) { return }
    Assert-DenCapAdministrator
    Invoke-DenCapTransaction $workspace $ica $module {
        Assert-DenCapNotRunning
        $list = if ($after -eq '' -and $manifest.virtualDriverExOriginallyAbsent) { $null } else { [pscustomobject]@{ Kind = 'String'; Data = $after } }
        Set-DenCapRegistryValue $workspace.RegistryView $workspace.IcaPath 'VirtualDriverEx' $list
        foreach ($name in $script:DenCapFields.Keys) { Set-DenCapRegistryValue $workspace.RegistryView $workspace.ModulePath $name $null }
        Remove-DenCapEmptyRegistryKey $workspace.RegistryView $workspace.ModulePath
        if (Test-Path -LiteralPath $workspace.DllPath) { Remove-Item -LiteralPath $workspace.DllPath -Force }
        Remove-Item -LiteralPath $workspace.ManifestPath -Force
    }
    if (@(Get-ChildItem -LiteralPath $workspace.StateDirectory -Force).Count -eq 0) { Remove-Item -LiteralPath $workspace.StateDirectory }
    Write-Output 'DENCAP was unregistered and removed. Other Citrix virtual channels were preserved.'
}
