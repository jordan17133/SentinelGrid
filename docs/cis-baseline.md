# CIS Benchmark Baseline: jordan-pc

| | |
|---|---|
| Benchmark | CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 (Wazuh SCA policy `cis_win11_enterprise.yml`, 482 checks) |
| Date | 2026-10-01 |
| Before | **27.1%** (128 passed, 345 failed, 9 not applicable) |
| After | **37.0%** (175 passed, 298 failed, 9 not applicable) |
| Change | 47 checks fixed, 0 regressions, 1 deliberately accepted |
| Script | [windows/Set-SentinelGridHardening.ps1](../windows/Set-SentinelGridHardening.ps1) (saves prior state; `-Revert` restores it) |
| Raw results | [cis/before-2026-10-01.json](cis/before-2026-10-01.json), [cis/after-2026-10-01.json](cis/after-2026-10-01.json) |

The benchmark targets domain-joined, centrally managed corporate machines, so a standalone home PC scoring low is expected. The goal was not 100%: it was to apply every change that is low-risk and genuinely useful for this PC, and to record a reason for each one left alone.

## Results by section

| Section | Before | After |
|---|---|---|
| 1 Account Policies | 1/8 (12%) | 4/8 (50%) |
| 2 Local Policies | 37/64 (58%) | 47/64 (73%) |
| 5 System Services | 12/39 (31%) | 14/39 (36%) |
| 9 Windows Firewall | 6/23 (26%) | 15/23 (65%) |
| 17 Advanced Audit Policy | 9/27 (33%) | 25/27 (93%) |
| 18 Administrative Templates | 63/312 (20%) | 70/312 (22%) |

## Applied

| Change | CIS | Why it matters here |
|---|---|---|
| Advanced audit policy for 16 subcategories (credential validation, account and group changes, lockouts, logon/logoff, USB and Plug and Play, file shares, scheduled tasks and other object access, firewall rule and policy changes, IPsec, security system extensions) | 17.x | Windows records these to the Security log, which Wazuh already collects. The biggest single gain in what the SOC can see. |
| Firewall logging of dropped packets, 16 MB per profile | 9.1.4-6, 9.2.4-6, 9.3.6-8 | A record of blocked inbound attempts |
| Account lockout: 5 attempts, 15 minutes, 15-minute reset | 1.2.1, 1.2.2, 1.2.4 | Slows password guessing against local accounts |
| NTLMv2 only, 128-bit NTLM session security, NTLM auditing, no anonymous SAM and share enumeration, no insecure SMB guest logons, machine identity for NTLM | 2.3.10.3, 2.3.11.1, 2.3.11.7, 2.3.11.9-12, 18.6.8.1 | Removes legacy authentication that is easy to abuse |
| UAC: prompt on the secure desktop for every elevation, Admin Approval Mode for the built-in Administrator, deny elevation for standard users | 2.3.17.1-3 | Closes the silent auto-elevation path that most UAC bypasses rely on |
| No custom SSPs/APs loaded into LSASS | 18.9.26.1 | Blocks a credential-theft persistence technique |
| AutoPlay off for all drives, no AutoRun commands, no AutoPlay for non-volume devices | 18.10.7.1-3 | Removes a classic USB malware vector |
| Print Spooler disabled (no printer), remote print endpoint off, UPnP Device Host disabled, Solicited Remote Assistance off | 5.17, 5.31, 18.7.1, 18.9.35.2 | Fewer exposed services; Remote Assistance is a common tech-support-scam vector |

## Accepted (not changed), with reasons

| Item | CIS | Reason |
|---|---|---|
| LSASS protection "with UEFI lock" | 18.9.26.2 | LSASS already runs as a protected process (`RunAsPPL=2`, the Windows 11 default). The UEFI lock only makes it harder to undo, which is the wrong trade on a personal PC. |
| Audit Process Creation | 17.3.2 | Sysmon event 1 already records every process with command line, hashes and parent, in more detail. |
| Audit Sensitive Privilege Use | 17.8.1 | Very high volume on a desktop for little added value. |
| Log successful firewall connections | 9.x.7 | Every allowed connection; noise outweighs value. |
| PowerShell transcription | 18.10.86.2 | Script block logging (event 4104) is already on and collected by Wazuh, without writing transcripts containing anything typed to disk. |
| Password history, minimum age, minimum length 14 | 1.1.x | Designed for shared enterprise accounts. A password manager with unique passwords and multi-factor authentication does more for a single user. |
| Block local firewall rules on public networks | 9.3.4-5 | Breaks games and game launchers on public Wi-Fi. |
| Domain and enterprise-only settings (Kerberos encryption types, hardened UNC paths, Application Guard, which is deprecated on Windows 11) | various | No domain; feature not applicable. |
| Credential Guard, SmartScreen "prevent bypass" | 18.9.5.5, 18.10.75.2.1 | Worth doing, deferred: they need compatibility testing with this PC's games, anti-cheat and Hyper-V. |
| Remaining Administrative Templates | 18.x | Mostly enterprise controls (telemetry, cloud content, Windows Update for Business, browser policies). To be reviewed in smaller batches. |

## What went wrong, and how it was found

The first run fixed 31 checks but none of the 16 audit settings. It took five runs of the script to find out why:

1. **Wazuh reported no change** for the audit checks: SCA only sends an alert when a result changes, and their last alert was from the first scan. The dashboard's live view agreed (scan finished after the change, still failing), so the problem was real, not a reporting lag.
2. **The Wazuh agent was undoing the change.** The SCA check runs `auditpol /get` and expects "Success and Failure"; run by hand afterwards, it showed "No Auditing". With FIM `whodata` enabled, the agent saves the audit policy when it starts and restores that copy when it stops. The script restarted the agent after changing the policy, so the agent put the old policy back. Fix: stop the agent, change the policy, then start it, so the agent saves the new policy as its restore point.
3. **Two subcategories still reverted** (Credential Validation, Application Group Management): the script verified all 16 as set, and seconds later those two read "No Auditing". The only thing in between was `net accounts` setting the lockout policy. Moving the lockout change before the audit change made all 16 stick. The mechanism inside Windows was not determined; the ordering is recorded in the script.
4. Verified by Wazuh's own rescan: 175 passed, all 16 audit checks passing.

Lesson for any SOC: the monitoring agent itself changes the system it monitors, and a configuration change is not done until the scanner that measures it agrees.
