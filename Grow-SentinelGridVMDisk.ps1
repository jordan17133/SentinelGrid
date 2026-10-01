#Requires -RunAsAdministrator
<#
  Grows the SentinelGrid-Wazuh VM's virtual disk. Safe to run while the VM is
  running (Generation 2 VMs support expanding a SCSI-attached VHDX online).

  Hyper-V cannot resize a disk that has checkpoints, because the VM is then
  writing to a differencing disk (.avhdx). Without -RemoveCheckpoints the script
  lists them and stops; with it, it merges them first. Take a new checkpoint
  after the disk and filesystem are grown.

  Afterwards, grow the partition and filesystem inside Ubuntu (see the runbook).
#>
param(
    [int]$NewSizeGB = 150,
    [switch]$RemoveCheckpoints
)
$ErrorActionPreference = 'Stop'
$vmName = 'SentinelGrid-Wazuh'

$vm = Get-VM -Name $vmName
$checkpoints = @(Get-VMCheckpoint -VM $vm)
if ($checkpoints.Count -gt 0) {
    "Checkpoints on ${vmName}:"
    $checkpoints | ForEach-Object { "  $($_.Name)  (created $($_.CreationTime))" }
    if (-not $RemoveCheckpoints) {
        throw "Hyper-V cannot resize a disk that has checkpoints. Re-run with -RemoveCheckpoints to merge them first."
    }
    "Merging checkpoints into the base disk..."
    $checkpoints | Remove-VMCheckpoint
}

# Wait for the merge: the attached disk switches from .avhdx back to the base .vhdx.
$deadline = (Get-Date).AddMinutes(30)
do {
    $disk = Get-VMHardDiskDrive -VMName $vmName | Select-Object -First 1
    $merging = (Get-VM -Name $vmName).Status -match 'Merg'
    if ($disk.Path -like '*.vhdx' -and -not $merging) { break }
    if ((Get-Date) -gt $deadline) { throw "Merge still running after 30 minutes. Disk: $($disk.Path)" }
    Start-Sleep -Seconds 5
} while ($true)

$vhd = Get-VHD -Path $disk.Path
$currentGB = [math]::Round($vhd.Size / 1GB)
if ($NewSizeGB -le $currentGB) { throw "Disk is already ${currentGB} GB; choose a larger -NewSizeGB." }

"Resizing $($disk.Path) from ${currentGB} GB to ${NewSizeGB} GB..."
Resize-VHD -Path $disk.Path -SizeBytes ([int64]$NewSizeGB * 1GB)

$vhd = Get-VHD -Path $disk.Path
[pscustomobject]@{
    Disk          = $disk.Path
    VirtualSizeGB = [math]::Round($vhd.Size / 1GB)
    FileSizeGB    = [math]::Round($vhd.FileSize / 1GB, 1)
    Checkpoints   = @(Get-VMCheckpoint -VMName $vmName).Count
} | Format-List
"Next: grow the partition and filesystem inside Ubuntu."
