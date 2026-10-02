# Baseline Review: Every Remaining Rule Behind a Fired ATT&CK Technique

| Field | Value |
|---|---|
| Date | 2026-10-01 |
| Analyst | Jordan Carven-Bellace |
| Hosts | jordan-pc (agent 001), wazuh (agent 000) |
| Scope | 28 rules that were the main rule behind a fired technique on the ATT&CK Coverage page but had no triage verdict |
| Verdict | **27 benign with a named source; 1 low-risk with the source process not confirmed.** No tuning. |

## Why this review

The ATT&CK Coverage page lists every technique that fired, with the triage verdict of the rule behind it. After the first four reports, the highest-volume rows still read "Not triaged". A technique firing is not the same as being attacked, but that claim needs evidence, so each rule was grouped by the process, parent, path or account behind it.

How the evidence was gathered: Sysmon process alerts were grouped by parent and child image, file-integrity alerts by registry path, and SSH and PAM alerts by account. PowerShell script-block alerts (event 4104) were matched on the script text itself. One lesson came out of this: SQL Server's `JSON_VALUE` returns NULL for strings longer than 4,000 characters, so long script blocks have to be searched in the raw JSON. The first count came back as 0 of 54 for that reason and was redone.

## Level 8 and above

| Rule | Level | Alerts | Source | Verdict |
|---|---|---|---|---|
| 91823 PowerShell `Invoke-Command` | 14 | 2 | Same second (06:43:34 UTC) as the Windows troubleshooter's scripts from `C:\Windows\Temp\SDIAG_...` (rules 91820 and 92213 in the [previous report](2026-10-01-rules-92213-92217-after-tuning.md)); the script defines the troubleshooter library's `Test-Caller` function | Benign: Windows troubleshooter |
| 100110 SentinelGrid FIM: secret file changed | 12 | 3 | `c:\users\jordan\.ssh\sg-fim-test.txt` added, modified and deleted at 05:48 UTC: the planned test of the FIM rule | Benign: planned FIM test |
| 91809 PowerShell Base64 decoding | 10 | 54 | All 54 begin `$EncodedCommand = '...'`, the wrapper that Claude Code's PowerShell tool uses. Decoded, they are this build's own commands: `sqlcmd` queries, Power BI window checks, `Get-Service WazuhSvc` | Benign: build tooling. Not tuned, see below |
| 60227 New external device | 8 | 3 | "Headset (A50)", an audio endpoint, at 18:40 UTC | Benign: user's headset |
| 60182 Performance Monitor Users changed | 8 | 2 | A virtual service account (`S-1-5-80-...`) added to `Performance Monitor Users` at 19:39 and 19:41 UTC on 9/30, during the SQL Server 2025 install | Benign: SQL Server setup |
| 5902 New user added | 8 | 1 | `useradd` of `wazuh-dashboard` on the Wazuh server at 08:32 UTC on 9/30, during the Wazuh install | Benign: Wazuh install |

## Levels 3 to 6 (high volume)

| Rule | Alerts | Main sources | Verdict |
|---|---|---|---|
| 750 Registry value checksum changed | 552 | `Services\bam\State` (333: Windows' Background Activity Moderator, which records when programs last ran), `Services\W32Time` (70: time sync) | Benign: Windows keeping its own state |
| 594 Registry key checksum changed | 570 | `Services\TPM\WMI` (180), `Services\DeviceAssociationService` (159), `bam\State` (38), `W32Time` (36): Windows updating its own keys | Benign: Windows keeping its own state |
| 751 Registry value deleted | 10 | `Services\MozillaMaintenance` (8: the Firefox removal during posture work), `Services\SharedAccess` (2) | Benign: planned software removal |
| 92052 cmd started by an abnormal process | 527 | `claude.exe > cmd.exe` (240: Claude Code's shell tool), `RadeonSoftware.exe > RSServCmd.exe` (98: AMD software) | Benign: build tooling and AMD software |
| 92032 Suspicious cmd shell execution | 508 | `cmd.exe > powershell.exe` (236) and `cmd.exe > chcp.com` (184): how Claude Code's tools start a shell | Benign: build tooling |
| 92021 PowerShell deleting files | 100 | `wazuh-agent.exe > powershell.exe` (92): Wazuh's own CIS checks run `secedit /export` and then `Remove-Item` on the temp file | Benign: Wazuh SCA checks |
| 92066 SecEdit.exe in an unusual place | 93 | `powershell.exe > SysWOW64\SecEdit.exe` (92): the same CIS checks | Benign: Wazuh SCA checks |
| 91816 PowerShell reading environment variables | 55 | `secedit /export /cfg $env:TEMP\...` (44: CIS checks), Claude Code's script preamble (11) | Benign: SCA checks and build tooling |
| 91815 PowerShell process discovery | 25 | Claude Code's script preamble (20), `Get-Process PBIDesktop` (4), `Get-AppxPackage *PowerBI*` (1) | Benign: build tooling |
| 92200 Script file created in Temp | 96 | `ChatGPT.exe` (45), Python 3.14 (23) | Benign: desktop apps and build scripts |
| 92307 New service in the registry | 57 | `services.exe` (57): service installs during SQL Server, Sysmon and app updates | Benign: software installs |
| 5501 / 5715 PAM session opened / SSH login success | 200 / 155 | `j0dane` on the Wazuh server: the analyst's SSH sessions and the loader's tunnel | Benign: admin and loader |
| 5402 sudo to root | 41 | `j0dane`: administration of the Wazuh server | Benign: admin |
| 67028 Special privileges at logon | 31 | `DWM-1` (10), `MSSQLSERVER` (6) and other Windows and service logons | Benign: normal logons |
| 506 Wazuh agent stopped | 9 | Planned agent restarts during FIM and CIS work (the audit policy had to be changed with the agent stopped) | Benign: planned |
| 92036 `net.exe` started by cmd | 2 | `net stop Wazuh` and `net start Wazuh` at 06:17 and 06:20 UTC | Benign: planned |
| 92006 `csc.exe` compiling | 8 | Covered in the [previous report](2026-10-01-rules-92213-92217-after-tuning.md) (`Add-Type` by build tooling) | Benign: build tooling |
| 91819 / 91820 PowerShell file searching | 2 / 2 | Claude Code's script preamble; the Windows troubleshooter's `Test-UnnecessaryFiles` | Benign |
| 60669 / 67018 Search service stopped / shutdown | 2 / 2 | The two restarts on 10/1 (Defender offline scan at 00:44, user restart at 02:06 local) | Benign: planned |

## Not confirmed: rule 67017, network share accessed (7 alerts)

`C$` and `IPC$` were opened over loopback (`::1`) by the user's own account at 16:42, 17:26, 17:27 and 19:02 UTC. Event 5140 does not record which process opened the share, and no PowerShell script block or Sysmon process alert falls within 10 seconds of any of them. The times fall inside build sessions, and loopback access to your own admin share needs your own logon, so the risk is low. But the source is **inferred, not proven**.

**Next step if it repeats:** enable the Sysmon network-connection event for port 445 on loopback, or the "Detailed File Share" audit subcategory (event 5145), which records the file accessed and makes the source easier to identify.

## A decision: build tooling stays visible

About 800 of the alerts reviewed here and in the previous report come from the AI coding assistant used to build the lab: shells, base64-encoded commands, process discovery and `Add-Type`. None of it is tuned out. The only thing that separates it from an attacker using the same techniques is a parent process name or a script prefix, and an attacker can copy both. On a real network, the fix is an allow-list tied to a signed binary and a known user, reviewed regularly. On a one-person lab, the honest choice is to leave it visible and documented.

## Verdict

All 28 rules now have a verdict on the ATT&CK Coverage page. 27 are benign with a named source. Rule 67017 is low-risk, and its source process is not confirmed.
