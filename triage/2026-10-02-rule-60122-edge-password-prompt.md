# Triage Report: Two Failed Windows Logons from Microsoft Edge

| Field | Value |
|---|---|
| Date | 2026-10-02 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc |
| Rule | 60122, "Logon Failure - Unknown user or bad password" (Windows Security event 4625, level 5) |
| Volume | 2 alerts, 21:44:54 and 21:45:02 UTC, 8 seconds apart |
| MITRE ATT&CK | T1531, Account Access Removal (how Wazuh maps this rule) |
| Verdict | **Benign, confirmed with the user:** a mistyped Windows password at Edge's saved-password prompt. |

## Investigation

| Field | Value | Meaning |
|---|---|---|
| Account | the machine owner's local account | A real account, not a guessed name |
| Logon type | 2 | Interactive: typed at this computer, not over the network |
| Status / sub-status | `0xc000006d` / `0xc000006a` | Correct username, wrong password |
| Process | `msedge.exe` via `Advapi` | Microsoft Edge asked Windows to verify a password |
| Source IP | none | Local only |

Edge asks for the Windows password before it shows or fills a saved password. The user confirmed that around that time Edge prompted for their Windows password and it was mistyped. Two failures stayed under the account lockout threshold of 5 set during CIS hardening.

**What would have changed the verdict:** failures over the network (logon type 3 or 10), from an unknown source IP, against several account names, or continuing until lockout; or a success right after many failures from a source the user did not recognize.

## Verdict

Benign, user-confirmed. No action needed.
