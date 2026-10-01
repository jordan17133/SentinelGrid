$ErrorActionPreference = "Stop"

$vmName = "SentinelGrid-Wazuh"
$vmRoot = "C:\Hyper-V\SentinelGrid-Wazuh"
$vhdPath = Join-Path $vmRoot "SentinelGrid-Wazuh.vhdx"
$isoPath = "C:\Users\Jordan\Downloads\ubuntu-24.04.5-live-server-amd64.iso"
$switchName = "Default Switch"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

if (-not (Test-Path -LiteralPath $isoPath)) {
    throw "Ubuntu installer not found at $isoPath"
}

if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    throw "A Hyper-V VM named $vmName already exists. No changes were made."
}

if (-not (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
    throw "Hyper-V's Default Switch was not found. No VM was created."
}

New-Item -ItemType Directory -Path $vmRoot -Force | Out-Null

$vm = New-VM `
    -Name $vmName `
    -Generation 2 `
    -MemoryStartupBytes 8GB `
    -NewVHDPath $vhdPath `
    -NewVHDSizeBytes 50GB `
    -Path $vmRoot `
    -SwitchName $switchName

Set-VMProcessor -VM $vm -Count 4
Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -AutomaticStartAction StartIfRunning -AutomaticStopAction Save

$dvd = Add-VMDvdDrive -VM $vm -Path $isoPath -Passthru
Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority -FirstBootDevice $dvd

Start-VM -VM $vm

[pscustomobject]@{
    Name = $vm.Name
    State = $vm.State
    CPU = 4
    RAM_GB = 8
    Disk_GB = 50
    ISO = $isoPath
} | Format-List
