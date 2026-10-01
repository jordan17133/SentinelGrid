# Triage Report: High-Severity "Executable Dropped" Alerts During Lab Setup

| Field | Value |
|---|---|
| Date | 2026-09-30 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc (Windows 11, Wazuh agent + Sysmon) |
| SIEM | Wazuh 4.14.8 (all-in-one, Ubuntu 24.04 VM) |
| Verdict | **False positive: benign administrative activity** |
| Severity (as fired) | Level 15 (maximum) |

## Summary

Minutes after the Wazuh agent and Sysmon were installed on `jordan-pc`, Wazuh raised three level 15 alerts from rule **92213**, "Executable file dropped in folder commonly used by malware." Investigation traced every alert to the two legitimate installers run during setup. No malicious activity was found.

## Alerts in scope

| Time (local) | Rule ID | Level | Description |
|---|---|---|---|
| 04:46:59 | 92066 | 4 | SecEdit.exe binary in a suspicious location |
| 04:46:59 to 04:47:01 | 92205 | 9 | PowerShell process created an executable file in Windows root folder |
| 04:47:01 | 92031 | 3 | Discovery activity executed (x4) |
| 04:47:09 | 92213 | 15 | Executable file dropped in folder commonly used by malware |
| 04:49:02 | 92213 | 15 | Executable file dropped in folder commonly used by malware (x2) |

MITRE ATT&CK techniques tagged: Ingress Tool Transfer (T1105), PowerShell (T1059.001), File Deletion (T1070.004), Account Discovery (T1087).

## Investigation

1. Filtered Threat Hunting to `rule.level >= 12` and reviewed the three rule 92213 events.
2. Opened each event and checked `data.win.eventdata.image`, the process that wrote the file.
   - One set was written by **msiexec.exe**, the Windows Installer, running the Wazuh agent MSI that the deployment command downloads to the user's Temp folder.
   - The other set was written by **Sysmon**, which copies its binary and driver into place during `Sysmon64.exe -i`.
3. Compared timestamps with the setup timeline. Every alert falls within the minutes when Sysmon and the Wazuh agent were being installed by the analyst.
4. The lower-severity alerts fit the same activity: `Invoke-WebRequest` fetching the Sysmon config (Ingress Tool Transfer), Sysmon copying itself into `C:\Windows\` (rule 92205), and installer account lookups (Discovery).

## Why the rule fired

Rule 92213 looks at **where** an executable is written, not whether the file is malicious. Temp and AppData folders are favorite staging locations for malware droppers, so any executable landing there is flagged at the highest level. Legitimate installers use the same folders, which makes this rule prone to false positives during software installation.

## Verdict and follow-up

- **Verdict:** False positive. Activity was authorized installation of security tooling by the system owner.
- **Action taken:** None needed on the host.
- **Tuning consideration:** Suppressing rule 92213 is not recommended, since it catches real dropper behavior. A narrow exception for signed `msiexec.exe` installs of known packages could reduce noise later, but only after a baseline of normal activity exists.
- **Lesson:** Expect a burst of high-severity alerts whenever new software is deployed. Correlating alert times with a change log is the fastest way to clear them.
