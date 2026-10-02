# Triage Report: Eleven Scheduled Tasks Created in One Day

| Field | Value |
|---|---|
| Date | 2026-10-02 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc |
| Rule | 60228, "A scheduled task was created" (Windows Security event 4698, level 4) |
| Volume | 11 alerts: 2 at 07:02 UTC, 9 at 15:39 UTC |
| MITRE ATT&CK | T1053, Scheduled Task/Job |
| Verdict | **Benign: a signed AMD software update and an authorized, documented migration.** |

## Summary

A 37th ATT&CK technique appeared on the coverage page: T1053, from rule 60228. Creating a scheduled task is one of the most common ways attackers keep a foothold, so every new task should be explainable. All eleven are.

## Investigation

1. **The 9 tasks at 15:39 UTC** (the automation workload's watchdogs and scheduled jobs; names withheld in the public copy) were created by the user's own account during the scheduled automation workload's migration to a new folder and Python 3.13. The change is recorded in the build log (2026-10-02), and each task was checked afterwards: all point at the new folder's Python 3.13 environments.
2. **The 2 tasks at 07:02 UTC** (`AMD Install Manager - Check For Updates`, `AMD Install Manager - Install Updates`) were created by the computer's system account. In the same second, Windows Installer logged "Application installed: AMD Install Manager" (events 11707 and 1033). `InstallManagerApp.exe` is validly signed by Advanced Micro Devices. The tasks are no longer registered under those names, consistent with an updater that manages its own tasks.
3. **What an attack would look like instead:** a task created by an unexpected account or process, pointing at a script interpreter, an unsigned binary, or a user-writable folder, with no matching install or change record.

## Verdict

Benign. Every new task maps to a signed vendor install or a documented change by the system owner. The rule stays at its default level: task creation is low-volume here and worth seeing.
