#Requires -RunAsAdministrator
<#
  Applies the CIS Windows 11 benchmark items chosen for jordan-pc (see
  docs/cis-baseline.md for what was applied, what was skipped, and why).

  Before changing anything it saves the current state to
  C:\ProgramData\SentinelGrid\cis-backup\ (audit policy, lockout policy, every
  registry value it touches, service start types). -Revert restores all of it.

  Usage (elevated):  .\Set-SentinelGridHardening.ps1
          undo:      .\Set-SentinelGridHardening.ps1 -Revert
  Changes apply immediately; no restart needed. (LSA protection, RunAsPPL=2, is
  already the Windows 11 default and is re-asserted here.) The script ends by
  restarting the Wazuh agent so the CIS scan re-scores the machine right away.
#>
param([switch]$Revert)
$ErrorActionPreference = 'Stop'
$backupDir = 'C:\ProgramData\SentinelGrid\cis-backup'
$stateFile = Join-Path $backupDir 'state.json'
$auditFile = Join-Path $backupDir 'auditpol.csv'

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$fw  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
$registry = @(
    # Account and NTLM hardening
    @{ Cis='2.3.10.3';  Path=$lsa; Name='RestrictAnonymous'; Value=1 }
    @{ Cis='2.3.11.1';  Path=$lsa; Name='UseMachineId'; Value=1 }
    @{ Cis='2.3.11.7';  Path=$lsa; Name='LmCompatibilityLevel'; Value=5 }
    @{ Cis='2.3.11.9';  Path="$lsa\MSV1_0"; Name='NTLMMinClientSec'; Value=537395200 }
    @{ Cis='2.3.11.10'; Path="$lsa\MSV1_0"; Name='NTLMMinServerSec'; Value=537395200 }
    @{ Cis='2.3.11.11'; Path="$lsa\MSV1_0"; Name='AuditReceivingNTLMTraffic'; Value=2 }
    @{ Cis='2.3.11.12'; Path="$lsa\MSV1_0"; Name='RestrictSendingNTLMTraffic'; Value=1 }
    @{ Cis='18.6.8.1';  Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name='AllowInsecureGuestAuth'; Value=0 }
    # LSASS protection (2 = enabled without UEFI lock, so it stays reversible)
    @{ Cis='18.9.26.2'; Path=$lsa; Name='RunAsPPL'; Value=2 }
    @{ Cis='18.9.26.1'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowCustomSSPsAPs'; Value=0 }
    # UAC
    @{ Cis='2.3.17.1';  Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Value=1 }
    @{ Cis='2.3.17.2';  Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Value=2 }
    @{ Cis='2.3.17.3';  Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Value=0 }
    @{ Cis='(UAC)';     Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Value=1 }
    # AutoPlay / AutoRun
    @{ Cis='18.10.7.1'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Value=1 }
    @{ Cis='18.10.7.2'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Value=1 }
    @{ Cis='18.10.7.3'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Value=255 }
    # Remote access and printing
    @{ Cis='18.9.35.2'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Value=0 }
    @{ Cis='18.7.1';    Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='RegisterSpoolerRemoteRpcEndPoint'; Value=2 }
)
# Firewall logging of dropped packets for every profile (successful connections stay unlogged: too noisy).
foreach ($p in @(@{Key='DomainProfile'; File='domainfw.log'; Cis='9.1'}, @{Key='PrivateProfile'; File='privatefw.log'; Cis='9.2'}, @{Key='PublicProfile'; File='publicfw.log'; Cis='9.3'})) {
    $registry += @{ Cis="$($p.Cis).x"; Path="$fw\$($p.Key)\Logging"; Name='LogFilePath'; Value="%SystemRoot%\System32\logfiles\firewall\$($p.File)"; Type='String' }
    $registry += @{ Cis="$($p.Cis).x"; Path="$fw\$($p.Key)\Logging"; Name='LogFileSize'; Value=16384 }
    $registry += @{ Cis="$($p.Cis).x"; Path="$fw\$($p.Key)\Logging"; Name='LogDroppedPackets'; Value=1 }
}

$services = @(
    @{ Cis='5.17'; Name='Spooler' }    # no printer on this PC
    @{ Cis='5.31'; Name='upnphost' }   # UPnP Device Host
)

# Advanced audit policy: subcategory GUIDs are locale-independent.
$g = '-69ae-11d9-bed3-505054503030'
$audit = @(
    @{ Cis='17.1.1'; Guid="0cce923f$g"; S=1; F=1; Name='Credential Validation' }
    @{ Cis='17.2.1'; Guid="0cce9239$g"; S=1; F=1; Name='Application Group Management' }
    @{ Cis='17.2.3'; Guid="0cce9235$g"; S=1; F=1; Name='User Account Management' }
    @{ Cis='17.3.1'; Guid="0cce9248$g"; S=1; F=0; Name='Plug and Play Events' }
    @{ Cis='17.5.1'; Guid="0cce9217$g"; S=0; F=1; Name='Account Lockout' }
    @{ Cis='17.5.2'; Guid="0cce9249$g"; S=1; F=0; Name='Group Membership' }
    @{ Cis='17.5.5'; Guid="0cce921c$g"; S=1; F=1; Name='Other Logon/Logoff Events' }
    @{ Cis='17.6.1'; Guid="0cce9244$g"; S=0; F=1; Name='Detailed File Share' }
    @{ Cis='17.6.2'; Guid="0cce9224$g"; S=1; F=1; Name='File Share' }
    @{ Cis='17.6.3'; Guid="0cce9227$g"; S=1; F=1; Name='Other Object Access Events (incl. scheduled task creation)' }
    @{ Cis='17.6.4'; Guid="0cce9245$g"; S=1; F=1; Name='Removable Storage' }
    @{ Cis='17.7.3'; Guid="0cce9231$g"; S=1; F=0; Name='Authorization Policy Change' }
    @{ Cis='17.7.4'; Guid="0cce9232$g"; S=1; F=1; Name='MPSSVC Rule-Level Policy Change (firewall rules)' }
    @{ Cis='17.7.5'; Guid="0cce9234$g"; S=0; F=1; Name='Other Policy Change Events' }
    @{ Cis='17.9.1'; Guid="0cce9213$g"; S=1; F=1; Name='IPsec Driver' }
    @{ Cis='17.9.4'; Guid="0cce9211$g"; S=1; F=0; Name='Security System Extension' }
)

function Get-Lockout {
    $out = net accounts
    $val = { param($label) $line = $out | Where-Object { $_ -match "^$label" } | Select-Object -First 1; ($line -split ':\s*', 2)[1].Trim() }
    @{ Threshold = (& $val 'Lockout threshold') -replace 'Never', '0'
       Duration  = & $val 'Lockout duration'
       Window    = & $val 'Lockout observation window' }
}

if ($Revert) {
    if (-not (Test-Path $stateFile)) { throw "No backup found at $stateFile" }
    $state = Get-Content $stateFile -Raw | ConvertFrom-Json
    foreach ($r in $state.Registry) {
        if ($r.Existed) { Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type $r.Kind }
        elseif (Test-Path $r.Path) { Remove-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue }
    }
    foreach ($s in $state.Services) {
        Set-Service -Name $s.Name -StartupType $s.StartType
        if ($s.Status -eq 'Running') { Start-Service -Name $s.Name }
    }
    # Same ordering as apply: lockout first (it can reset account audit subcategories), and the
    # Wazuh agent stopped while audit policy changes (it restores its own saved copy when it stops).
    net accounts /lockoutthreshold:$($state.Lockout.Threshold) | Out-Null
    if ([int]$state.Lockout.Threshold -gt 0) {
        net accounts /lockoutduration:$($state.Lockout.Duration) /lockoutwindow:$($state.Lockout.Window) | Out-Null
    }
    Stop-Service -Name WazuhSvc
    Start-Sleep -Seconds 8
    auditpol /restore /file:$auditFile | Out-Null
    Start-Service -Name WazuhSvc
    "Reverted to the settings saved on $($state.SavedAt)."
    return
}

# ---- Save current state (only once, so re-running never overwrites the original backup) ----
if (-not (Test-Path $stateFile)) {
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    auditpol /backup /file:$auditFile | Out-Null
    $state = [ordered]@{
        SavedAt  = (Get-Date).ToString('s')
        Lockout  = Get-Lockout
        Services = @($services | ForEach-Object { $svc = Get-Service $_.Name; @{ Name=$_.Name; StartType=[string]$svc.StartType; Status=[string]$svc.Status } })
        Registry = @($registry | ForEach-Object {
            $item = Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
            if ($null -ne $item) {
                @{ Path=$_.Path; Name=$_.Name; Existed=$true; Value=$item.($_.Name); Kind=[string](Get-Item $_.Path).GetValueKind($_.Name) }
            } else { @{ Path=$_.Path; Name=$_.Name; Existed=$false } }
        })
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding UTF8
    "Saved current settings to $backupDir"
} else {
    "Backup already exists from an earlier run; keeping the original."
}

# ---- Apply ----
foreach ($r in $registry) {
    if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
    $type = if ($r.Type) { $r.Type } else { 'DWord' }
    Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type $type
}
foreach ($s in $services) {
    Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $s.Name -StartupType Disabled
}
# Lockout policy before audit policy: observed on this PC, changing the lockout policy
# reset two account-related audit subcategories that had already been verified as set.
net accounts /lockoutthreshold:5 | Out-Null
net accounts /lockoutduration:15 /lockoutwindow:15 | Out-Null
Start-Sleep -Seconds 5
# The Wazuh agent (FIM whodata) saves the audit policy when it starts and restores
# that copy when it stops. Setting audit policy while it runs gets undone at its next
# stop, so: stop the agent, set the policy, then start it so it saves the new policy.
Stop-Service -Name WazuhSvc
# The agent's restore runs in the background while it shuts down; let it finish first.
$deadline = (Get-Date).AddSeconds(60)
do { Start-Sleep -Seconds 3 } while ((Get-Process auditpol -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline)
Start-Sleep -Seconds 5

function Test-AuditSet($a) {
    $l = auditpol /get "/subcategory:{$($a.Guid)}" /r 2>&1 | ConvertFrom-Csv | Select-Object -First 1
    if (-not $l) { return $false }
    $want = if ($a.S -and $a.F) { 'Success and Failure' } elseif ($a.S) { 'Success' } else { 'Failure' }
    $l.'Inclusion Setting' -eq $want -or $l.'Inclusion Setting' -eq 'Success and Failure'
}
$auditFailures = 0
foreach ($attempt in 1..3) {
    $pending = @($audit | Where-Object { -not (Test-AuditSet $_) })
    if (-not $pending) { break }
    foreach ($a in $pending) {
        $auditArgs = @('/set', "/subcategory:{$($a.Guid)}")
        if ($a.S) { $auditArgs += '/success:enable' }
        if ($a.F) { $auditArgs += '/failure:enable' }
        $out = (auditpol @auditArgs 2>&1) -join ' '
        if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol could not set '$($a.Name)' (exit $LASTEXITCODE): $out" }
    }
    Start-Sleep -Seconds 2
}
$auditFailures = @($audit | Where-Object { -not (Test-AuditSet $_) }).Count

# ---- Report ----
"Applied: $($registry.Count) registry values, $($services.Count) services disabled, $($audit.Count - $auditFailures)/$($audit.Count) audit subcategories, account lockout 5 attempts / 15 minutes."
"Audit policy as Windows now reports it:"
foreach ($a in $audit) {
    $line = auditpol /get "/subcategory:{$($a.Guid)}" /r 2>&1 | ConvertFrom-Csv | Select-Object -First 1
    "  {0,-60} {1}" -f $a.Name, $(if ($line) { $line.'Inclusion Setting' } else { 'unreadable' })
}
$lock = Get-Lockout
"Lockout now: threshold=$($lock.Threshold) duration=$($lock.Duration) window=$($lock.Window)"
$services | ForEach-Object { $svc = Get-Service $_.Name; "Service $($_.Name): $($svc.Status), $($svc.StartType)" }
"RunAsPPL = $((Get-ItemProperty $lsa).RunAsPPL)   ConsentPromptBehaviorAdmin = $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin)"

# Start the agent: it saves the new audit policy as its restore point, adds its own
# file-auditing subcategories for whodata, and runs a fresh CIS scan.
Start-Service -Name WazuhSvc
Start-Sleep -Seconds 15
$kept = @($audit | Where-Object {
    $l = auditpol /get "/subcategory:{$($_.Guid)}" /r 2>&1 | ConvertFrom-Csv | Select-Object -First 1
    $l -and $l.'Inclusion Setting' -ne 'No Auditing'
}).Count
"Wazuh agent started. Audit subcategories still set after the agent started: $kept/$($audit.Count)"
"A fresh CIS scan is running; results arrive within a few minutes."
