# Triage Report: Hourly "Application Compatibility Database Launched" Alerts

| Field | Value |
|---|---|
| Date | 2026-09-30 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc |
| Rule | 92058, "Application Compatibility Database launched" (level 12, High) |
| Volume | 15 alerts, one per hour at :53, 04:53 to 18:53 |
| MITRE ATT&CK | T1546.011, Event Triggered Execution: Application Shimming |
| Verdict | **False positive: built-in Windows maintenance.** Tuned. |

## Summary

A review of every Critical and High alert in the Watchtide warehouse found one High-severity pattern not yet explained: `sdbinst.exe` launching once an hour. Attackers can abuse `sdbinst.exe` to install a malicious compatibility "shim" database that injects code into other programs and survives reboots, which is why Wazuh rates it High. Investigation showed a genuine, Microsoft-signed binary started by Windows' own Program Compatibility Assistant service with its standard background-merge arguments.

## Investigation

1. **Pattern:** 15 alerts at exactly :53 past each hour, including overnight. A fixed schedule points to a system timer, not a person.
2. **Process details** (from the stored raw alert):

   | Field | Value |
   |---|---|
   | Image | `C:\Windows\System32\sdbinst.exe` |
   | Command line | `sdbinst.exe -m -bg` (merge, in the background) |
   | Parent | `svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc` |
   | User / integrity | `NT AUTHORITY\SYSTEM` / System |
   | Company / original name | Microsoft Corporation / `sdbinst.exe` |
   | SHA-256 | `8F67CBBDB8250CEDA1E5DB21DF87AD870576229B8FD729E80F9092EB578B6915` |

3. **Signature check on the host:** `Get-AuthenticodeSignature` reports **Valid**, signed by `CN=Microsoft Windows`. The file is in its expected location, `System32`.
4. **Parent service:** `PcaSvc` is the Program Compatibility Assistant, a built-in Windows service. Windows also ships a related scheduled task, `\Microsoft\Windows\Application Experience\SdbinstMergeDbTask` (`sdbinst.exe -mm`).
5. **What an attack would look like instead:** a shim install uses `sdbinst.exe` with a path to a `.sdb` file (for example `sdbinst.exe -q C:\Users\...\evil.sdb`), usually started by a user process or script, not by `PcaSvc` with `-m -bg`. None of the 15 events looked like that.

## Tuning

Rule **100101** in [wazuh/rules/sentinelgrid_tuning.xml](../wazuh/rules/sentinelgrid_tuning.xml) lowers this exact pattern to level 3. It only matches when **all four** hold: the image is `System32\sdbinst.exe`, the command line is exactly `sdbinst.exe -m -bg`, the parent is the `PcaSvc` service host, and the user is SYSTEM. Any other `sdbinst.exe` use, including installing a `.sdb` file, still fires rule 92058 at level 12.

**Residual risk:** an attacker with SYSTEM rights could mimic this exact command line. At that point they already fully control the machine, and `-m -bg` does not install a new shim, so the tuning does not widen the realistic attack path.

## Verdict

False positive. Benign scheduled Windows maintenance. No action needed on the host.
