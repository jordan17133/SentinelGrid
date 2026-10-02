# Triage Report: Run-Key Autostart Change at 1:36 AM

| Field | Value |
|---|---|
| Date | 2026-10-02 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc |
| Rule | 100113, "Watchtide FIM: Run key autostart entry changed" (level 10, custom) |
| Volume | 2 alerts (the 64-bit and 32-bit registry views of the same value), 05:36:33 UTC |
| MITRE ATT&CK | T1547.001, Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Verdict | **Benign: Microsoft Edge updated its own startup entry.** No tuning. |

## Summary

A routine morning check of the ATT&CK Coverage page showed a 36th technique, not yet triaged: T1547.001, raised by Watchtide's own file integrity rule for the user's Run key. Programs listed there start at every logon, which is why attackers use it for persistence. The changed value was Microsoft Edge's own auto-launch entry, rewritten by Edge to add a startup flag.

## Investigation

1. **What changed:** `HKEY_USERS\<user SID>\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeAutoLaunch_1B77D526...` was modified; size 166 to 206 bytes, with the old and new hashes recorded in the alert.
2. **Current value:** `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start`, 102 characters, which is exactly 206 bytes as a registry string. The 40-byte growth is the 20-character `--win-session-start` flag.
3. **Binary:** `Get-AuthenticodeSignature` reports **Valid**, signed by `CN=Microsoft Corporation`, in Edge's standard install folder. No other Run entries changed.
4. **Timing:** Edge wrote an event to the Application log at 01:30 local, six minutes before the change, consistent with Edge updating its own startup-boost setting.
5. **What an attack would look like instead:** a new or modified Run value pointing at an unsigned binary, a script interpreter (`powershell.exe -enc ...`, `wscript.exe`), or a path in a user-writable folder such as `AppData\Local\Temp`. None of that is present.

## Notes

- Registry monitoring runs in scheduled mode, so the alert cannot name the process that made the change; the timing and the value itself carry the evidence. A follow-up could add Sysmon event 13 (registry value set) for Run keys to capture the writing process.
- The rule did its job: an autostart change on this machine surfaced within one scan and was explained in minutes.

## Verdict

Benign. A signed Microsoft Edge entry updated by Edge itself. No action needed.
