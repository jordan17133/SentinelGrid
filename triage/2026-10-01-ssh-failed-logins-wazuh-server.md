# Incident Report: Failed SSH Logins Against the Wazuh Server (Controlled Test)

| Field | Value |
|---|---|
| Date | 2026-10-01 |
| Analyst | Jordan Carven-Bellace |
| Host | wazuh (the Wazuh server itself, agent 000) |
| Rules | 5710 (level 5), 5503 (level 5), 5760 (level 5), **2502 (level 10)** |
| Volume | 6 failure alerts in 26 seconds, 21:31:40 to 21:32:06 UTC |
| MITRE ATT&CK | T1110.001, Brute Force: Password Guessing |
| Verdict | **True positive, authorized test.** No successful login by the tested accounts. |

## Summary

To check that the lab detects password guessing, the analyst made deliberate failed SSH logins against the Wazuh server: one attempt as a username that does not exist, then three wrong passwords for a real account. Wazuh read the attempts from the server's own `sshd` journal, raised six failure alerts mapped to ATT&CK T1110.001, and escalated to level 10 when one session failed three times. Every alert reached the SQL warehouse on the next scheduled load.

## Timeline (UTC)

| Time | Rule | Level | Source IP | Event (from the raw log line) |
|---|---|---|---|---|
| 21:31:24 | 5715 | 3 | 172.23.240.1 | `Accepted password for j0dane` (analyst's own session, port 52319) |
| 21:31:39 | **5710** | 5 | 172.23.240.1 | `Invalid user fakeuser` (port 62022) |
| 21:31:45 | 5715 | 3 | 172.23.240.1 | `Accepted password for j0dane` (port 62017) |
| 21:31:49 | 5503 | 5 | 172.23.250.216 | `pam_unix(sshd:auth): authentication failure ... user=j0dane` |
| 21:31:51 | 5760 | 5 | 172.23.250.216 | `Failed password for j0dane` (port 35552) |
| 21:31:56 | 5760 | 5 | 172.23.250.216 | `Failed password for j0dane` (same session) |
| 21:32:03 | 5760 | 5 | 172.23.250.216 | `Failed password for j0dane` (same session) |
| 21:32:05 | **2502** | 10 | 172.23.250.216 | `PAM 2 more authentication failures` (user missed the password more than once) |
| 21:42:42 | | | | Loader run inserts all of the above into `sg.alerts` |

Evidence `doc_id`s in the warehouse: `m2Vh-aABhN-3RaP0XyJy` (5710), `r2Vh-aABhN-3RaP0hiKC` (5503), `sGVh-aABhN-3RaP0iiJr`, `u2Vh-aABhN-3RaP0pCLn`, `wmVh-aABhN-3RaP0vCJZ` (5760), `xWVh-aABhN-3RaP0wCJA` (2502).

## Investigation

1. **Where the attempts came from.** 172.23.240.1 is the Windows host's address on the Hyper-V Default Switch. 172.23.250.216 is the Wazuh server's own address: the three wrong passwords were typed in an SSH session started from the server to itself.
2. **Did anyone get in?** This is the first question for any run of failures. Two successful logins appear in the window, both for `j0dane` from the Windows host. The `sshd` process IDs and source ports show they are separate connections from the failures: the success at 21:31:45 is process 31305 on port 62017, while the invalid-user attempt is process 31307 on port 62022. Both successes are the analyst's own sessions. No login as `fakeuser` was possible (the account does not exist), and the session that failed three times (process 31366) ended without a success.
3. **What fired and what did not.** Each failure raised its own alert, and rule 2502 escalated to level 10 when one session failed repeatedly. Wazuh's correlation rule for a brute-force burst (5712, eight or more failures from one IP within 120 seconds) did **not** fire, because the test made at most four failures from any single IP. That is correct behavior, and it also marks the limit of the default rules: slow guessing below that rate only produces level 5 and level 10 alerts, never a dedicated brute-force alert.
4. **Pipeline timing.** The last failure was logged at 21:32:05 and was in SQL after the 21:42:42 load, about 10.5 minutes later, in line with the 15-minute schedule (median alert-to-SQL latency is about 7 minutes).

## Exposure

- SSH on the Wazuh server accepts passwords, and `ufw` allows port 22 only from private ranges (10/8, 172.16/12, 192.168/16). There is no exposure to the internet.
- Wazuh active response (automatic IP blocking) is not enabled, so detection is alert-only.

## Recommendations

1. **Switch SSH to key-only logins** (`PasswordAuthentication no`) once the analyst has a key too. The loader tunnel already uses a restricted key, so only interactive logins still rely on passwords. This removes password guessing as a path entirely.
2. **Optionally enable active response** (`firewall-drop`) for rules 5712 and 5763, so a real burst is blocked automatically. Test it first: a mistake can lock out the loader tunnel.
3. **Optionally add a local rule** for repeated failures from one IP over a longer window (for example 5 failures in 10 minutes), to catch guessing that stays below rule 5712's rate.

## Verdict

True positive from an authorized test. Detection worked as designed for T1110.001 at the default thresholds, with one documented gap (slow guessing never reaches the brute-force rule). No compromise.
