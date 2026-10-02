# Triage Report: Recurring Level 15 Alerts From PowerShell Policy Test Files

| Field | Value |
|---|---|
| Date | 2026-09-30 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc |
| Rule | 92213, "Executable file dropped in folder commonly used by malware" (level 15) |
| Volume | 506 alerts in about 12 hours; 478 from one pattern |
| Verdict | **False positive: benign scheduled automation.** Tuning recommended. |
| Found by | SQL warehouse analysis, not the Wazuh dashboard |

## Summary

After the first load into the Watchtide SQL warehouse, rule 92213 accounted for every Critical-band alert: 506 in half a day. The [first 92213 triage](2026-09-30-rule-92213-installer-false-positive.md) covered three alerts during setup, so a steady stream of this volume needed its own investigation. 478 of the 506 were PowerShell writing its own execution-policy test file to the user's Temp folder, triggered by three automation watchdog tasks that start PowerShell every 5 minutes. The other 28 were software installs and uninstalls done on purpose that day.

## Investigation

1. **Volume by hour** (query on `rpt.alerts`): a flat 36 alerts per hour through the night and morning, when nobody was at the keyboard. A flat, round-the-clock rate points to automation, not a person.
2. **Process and file:** every one of the 478 was written by `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, and every file matched `C:\Users\Jordan\AppData\Local\Temp\__PSScriptPolicyTest_<random>.<random>.ps1`. PowerShell creates this file itself at startup to test whether AppLocker or WDAC script policy is enforced, then deletes it. So each PowerShell launch produces one alert.
3. **Finding the launcher:** Wazuh only indexes events that match a rule, and the PowerShell process-start events had no matching rule, so the parent process was not in the warehouse. A live 4-minute sample of running processes caught `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Apps\Automation\jobs\..."`.
4. **Confirming the cadence:** Task Scheduler has three enabled tasks that repeat every 5 minutes (`PT5M`): `JobAWatchdog`, `JobBWatchdog` and `AppWatchdog`. 3 tasks x 12 runs per hour = 36 PowerShell launches per hour, exactly matching the alert rate. The system owner confirmed these are their own automation watchdogs.
5. **The remaining 28:** `Un_A.exe` and `helper.exe` (Firefox uninstaller), `python-3.14.7-amd64.exe` (Python install via winget), and Steam's `hardwareupdater.exe`. All match changes made on purpose that afternoon.

## Why it matters

- **Alert fatigue:** 94% of the highest-severity alerts were one harmless pattern. A real dropper landing in Temp would be buried in the noise.
- **Reporting accuracy:** until tuned, any "Critical alerts" measure in Power BI mostly reflects how often a watchdog runs, not risk.
- **Visibility gap:** the parent process could only be found live, because only alerts, not all events, reach the Indexer. Keep this in mind for future hunts.

## Recommended tuning

Do **not** disable rule 92213; it catches real dropper behavior. Add a narrow child rule on the Wazuh server that lowers severity only when **both** conditions hold: the writer is Windows PowerShell and the file matches PowerShell's exact policy-test naming pattern.

The rule is rule **100100** in [wazuh/rules/sentinelgrid_tuning.xml](../wazuh/rules/sentinelgrid_tuning.xml). An earlier draft of this report matched path separators with a single escaped backslash (`\\`). Wazuh stores Windows eventdata with doubled backslashes (`C:\\Windows`), so that draft would never have matched. The deployed rule uses `\\\\`, the convention the stock Wazuh Sysmon rules use.

**Residual risk:** an attacker who already controls PowerShell could name a payload to match this pattern and get a level 3 alert instead of level 15. The strict pattern (exact random-name lengths, `.ps1` only, Temp only, Windows PowerShell only) keeps that window small, and the event is still recorded, just at lower severity.

## Verdict

False positive. No malicious activity. Tuning rule proposed; apply it and confirm that level 15 volume drops from about 36 per hour to near zero while the installer-driven 92213 alerts still fire.
