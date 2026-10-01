#Requires -RunAsAdministrator
<#
  Turns Windows PowerShell script block logging on (or off with -Disable).

  What it changes:
    1. Policy: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
       EnableScriptBlockLogging = 1. This is the same setting as the Group Policy
       "Turn on PowerShell Script Block Logging". Code is logged as event 4104 in
       Microsoft-Windows-PowerShell/Operational after deobfuscation.
       Invocation start/stop logging (4105/4106) stays off: very noisy, little value.
    2. Size of the Microsoft-Windows-PowerShell/Operational log: 15 MB default
       raised to 100 MB, so the local copy is not overwritten within hours.

  Everything run in PowerShell gets recorded, including any secret typed into a
  command. Never put passwords or API keys on a PowerShell command line.

  Usage (elevated):  .\Set-PowerShellScriptBlockLogging.ps1
          undo:      .\Set-PowerShellScriptBlockLogging.ps1 -Disable
#>
param([switch]$Disable)
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$log = 'Microsoft-Windows-PowerShell/Operational'

if ($Disable) {
    if (Test-Path $key) { Remove-Item $key -Recurse }
    "Script block logging policy removed (Windows default: only suspicious blocks are logged)."
} else {
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -Type DWord
    Set-ItemProperty -Path $key -Name EnableScriptBlockInvocationLogging -Value 0 -Type DWord
    wevtutil set-log $log /maxsize:104857600
    "Script block logging enabled."
}

$p = Get-ItemProperty $key -ErrorAction SilentlyContinue
[pscustomobject]@{
    EnableScriptBlockLogging = $p.EnableScriptBlockLogging
    InvocationLogging        = $p.EnableScriptBlockInvocationLogging
    OperationalLogMaxMB      = [math]::Round((Get-WinEvent -ListLog $log).MaximumSizeInBytes / 1MB)
} | Format-List
"New PowerShell sessions pick this up immediately; no restart needed."
