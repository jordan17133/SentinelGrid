# SentinelGrid Build Log

A running record of how the SentinelGrid home SOC lab was built, what broke, and how it was fixed. The step-by-step plan lives in [SentinelGrid-Build-Runbook.md](SentinelGrid-Build-Runbook.md). Alert investigations live in [triage/](triage/).

## Status at a glance (2026-10-01)

| Runbook stage | Status |
|---|---|
| 0. Prepare the lab (Hyper-V, Ubuntu VM) | Done |
| 1. Wazuh all-in-one stack | Done and hardened |
| 2. Sysmon on Windows | Done |
| 3. Wazuh agent on Windows | Done, agent `jordan-pc` is Active |
| 4. Prove the event path end to end | Done, traced through every layer (docs/event-trace.md) |
| 5. Suricata network telemetry | Not started |
| 6. SentinelGrid API on live Wazuh data | Not started (console still runs on generated demo data) |
| 4b. Posture review | Done: 445 vulnerability findings cut to 39 with zero Critical; CIS 27.1% to 37.0% |
| 7. SQL Server reporting storage | Done: loader every 15 minutes; case log with history (`warehouse/cases.py`) meets the incident gate |
| 8. Power BI report | Done: four pages built as a Power BI Project (definitions in Git, data cache ignored), ATT&CK catalog loaded |
| Detection validation | In progress: controlled SSH password-guessing test detected end to end; every Critical alert since tuning explained |

## What is running

```text
Windows 11 host (jordan-pc)
  Sysmon64 (SwiftOnSecurity config) -> Windows Event Log
  Wazuh agent 4.14.8 ------------------------------+
                                                   | TCP 1514/1515
Hyper-V VM "SentinelGrid-Wazuh" (Default Switch)   v
  Ubuntu Server 24.04.5, 4 vCPU, 8 GB RAM, 150 GB disk
  Wazuh manager -> Filebeat -> Wazuh indexer -> Wazuh dashboard (https://wazuh.mshome.net)
                                     ^ 127.0.0.1:9200 only
                                     | SSH tunnel (restricted key)
Windows host                         |
  Task Scheduler \SentinelGrid\SentinelGridLoader, every 15 min
    loader/wazuh_to_sql.py (Python 3.14 venv) -> SQL Server 2025 Developer
      SentinelGridWarehouse: sg.* tables, rpt.* views -> Power BI Desktop
```

- The loader reaches the Indexer through an SSH tunnel because the Indexer only listens on the VM's loopback address. Its SSH key is limited in `authorized_keys` to `permitopen="127.0.0.1:9200"` with `command="/bin/false"`, so it cannot open a shell (verified). Port 9200 stays closed in `ufw`.
- The loader signs in as `sentinelgrid_loader`, an Indexer user whose role can only read `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`. TLS is verified against the Wazuh root CA.
- SQL Server is capped at 4 GB of RAM because the Wazuh VM reserves 8 GB.

- The Sysmon event channel is collected through the `default` agent group's `agent.conf`, so every future agent in that group picks it up automatically.
- The VM is reached by hostname (`wazuh.mshome.net`) instead of IP, because Hyper-V's Default Switch hands out a new IP on every VM reboot.

## Timeline

### 2026-09-29: Planning and host prep
- Checked host capacity (Ryzen 9 8945HS, 28.8 GB RAM) against the Wazuh all-in-one minimum (4 vCPU, 8 GB RAM, 50 GB disk).
- Enabled Hyper-V with `Enable-SentinelGridHyperV.ps1`, downloaded Ubuntu Server 24.04.5, and verified the ISO's SHA-256 hash.
- Wrote `Create-SentinelGridWazuhVM.ps1` to build a Generation 2 VM with Secure Boot and fixed memory.

### 2026-09-30: Wazuh stack, endpoint telemetry, first triage
- Rebooted to activate Hyper-V, created the VM, and installed Ubuntu with OpenSSH.
- Installed Wazuh 4.14.8 with the assisted all-in-one installer (after fixing the failures below).
- Installed Sysmon with the SwiftOnSecurity configuration.
- Deployed the Wazuh Windows agent from the dashboard and confirmed it went from Pending to Active.
- Pushed the Sysmon collection config through the `default` group and confirmed Sysmon alerts in Threat Hunting: 31 alerts in 15 minutes, mapped to MITRE ATT&CK techniques T1105, T1059.001, T1070.004 and T1087.
- Investigated three level 15 alerts and closed them as false positives caused by the installers. See [the triage report](triage/2026-09-30-rule-92213-installer-false-positive.md).
- Hardened the VM (backup, admin password rotation, `ufw`, `wazuh-clean` checkpoint).

### 2026-09-30 (afternoon): Posture review, SQL warehouse, second triage
- **Vulnerability Detection baseline: 445 findings (99 Critical, 247 High, 91 Medium, 8 Low).** Firefox 146.0, unused since December 2025, caused 393 of them (88%).
- Uninstalled Firefox and the Mozilla Maintenance Service, upgraded pip, pypdf and idna, and installed Python 3.14 because Python 3.11 no longer gets Windows installers. **Result: 39 findings (0 Critical, 21 High, 16 Medium, 2 Low).** Remaining: Python 3.11.9 (16), Steam (8), and packages in the Python 3.11 environment (PyJWT, setuptools, cryptography, urllib3).
- Installed SQL Server 2025 Enterprise Developer (default instance `MSSQLSERVER`) and built `SentinelGridWarehouse` with idempotent scripts in `warehouse/sql/`.
- Wrote `loader/wazuh_to_sql.py`: incremental, keyed by Indexer document ID, with a 10-minute overlap window and a run log in `sg.load_runs`. First run loaded 2,306 alerts and 39 vulnerability findings; the second run fetched 473 overlapping alerts and inserted only the 1 new one.
- Warehouse analysis surfaced 506 level 15 alerts in 12 hours. 478 were PowerShell's own policy-test file, created every time three automation watchdog tasks started PowerShell every 5 minutes. See [the second triage report](triage/2026-09-30-rule-92213-powershell-policy-test-noise.md). A narrow tuning rule is proposed there.

### 2026-09-30 (night): Stage 4 trace, Defender telemetry, compromise sweep
- Stage 4 controlled test: traced one tagged `whoami` execution from Sysmon (event ID 1, record 44012) to Wazuh rule 92032 (0.5 seconds later), the Indexer, and the SQL warehouse (about a minute later), all joined by the Indexer document ID. Write-up: [docs/event-trace.md](docs/event-trace.md). Found two visibility gaps: Wazuh indexes only rule-matched events (Notepad's launch never reached it), and `nslookup` bypasses the DNS Client that Sysmon's DNS logging relies on.
- `GET _cat/indices/wazuh-*?v`: 18 indices, all green.
- Precautionary read-only compromise sweep: every startup entry, non-Microsoft scheduled task and auto-start service was signed by a known vendor or belonged to known software, and every live outbound connection was explained. Flagged three Chrome extensions with all-site access (one also reading cookies) for removal, and a discontinued startup app (Snap Camera).
- Added `Microsoft-Windows-Windows Defender/Operational` to the `default` group's `agent.conf`. The agent restarted itself and Wazuh then recorded the first full Defender scan end to end: rule 62108 "Antimalware scan finished" (Full Scan, 1:14:24, matching Windows Security), 66 cloud-lookup events, a platform health event, and no detection events. Windows Security agreed: 0 threats in 2,189,640 files.
### 2026-10-01: Full event archive and data lifecycle
- Grew the VM disk from 50 GB to 150 GB (`Grow-SentinelGridVMDisk.ps1` merged the two checkpoints, then expanded the VHDX online) and the Ubuntu filesystem to 145 GB (23 GB used).
- Turned on full event archiving (`logall_json` plus Filebeat archives). The first `wazuh-archives-*` index was green within minutes.
- Retention at every layer, so storage cannot grow without bound: ISM policies delete archive indices after 30 days and alert indices after 365 (all three existing indices confirmed managed); a nightly cron job recycles Wazuh's raw rotated logs (archives 7 days, alerts 90); the SQL warehouse keeps every alert row with permanent daily summaries under a 100 GB cap.
- Proof: Notepad launches now appear in Wazuh as Sysmon event ID 1, closing the visibility gap found in the Stage 4 trace.
- Observation: the Wazuh server's own dashboard web logs (one event per file the browser loads) are a large share of archive volume, and viewing the archive adds to it. Candidate for a filter.

### 2026-10-01: File integrity monitoring and archive noise filter
- **FIM on what matters most.** `wazuh/agent/default-agent.conf` (pushed through the `default` group) watches 21 paths with `whodata`, so every alert names the user and process behind a change. Tags: `sg-secrets` (automation app `.env` and API configs, loader `.env`, `.ssh`, the private Wazuh secrets folder), `sg-sched-exec` (every script Task Scheduler runs for the automation app), `sg-persistence` (both Startup folders, the user's Run and RunOnce keys). `report_changes` is deliberately off so secret contents never leave the PC. FIM sees changes, not reads.
- **Severity rules** in `wazuh/rules/sentinelgrid_fim.xml` raise those paths to level 12 (secrets, T1552.001; scheduled automation scripts, T1053.005) and level 10 (Startup folders and Run keys, T1547.001). Patterns were tested against all 24 monitored paths and 8 decoys first, which caught a regex bug (`runonce?` instead of `run(once)?`) before deployment.
- **Live test:** creating, editing and deleting a file in `.ssh` produced three alerts within about 2 seconds each: first at stock levels 5 and 7, then, after the rules, rule 100110 at level 12, each naming `Jordan` via `powershell.exe`.
- **Archive noise filter.** Measured first: journald was 22% of archived events, and the dashboard's own HTTP response logs were a large part of it, growing with every page viewed. Filtered at collection so logins, failed or denied requests (401/403) and dashboard errors are kept. Result while actively browsing and logging in: 14 dashboard lines in the archive versus 343 before, including the login. sshd and PAM events still arrive (verified with the loader's own SSH login).

### 2026-10-01: PowerShell script block logging
- Enabled with `windows/Set-PowerShellScriptBlockLogging.ps1` (run elevated; `-Disable` reverts): the Group Policy setting that records every PowerShell script block as event 4104, after deobfuscation, plus a larger local log (15 to 100 MB). Invocation logging (4105/4106) left off as noise.
- Collected through the `default` group's `agent.conf`, with an event channel query that ships only event 4104.
- Verified at every hop: the policy and log size on Windows, the agent receiving the new config, a tagged test command recorded locally as event 4104, and 61 script blocks in `wazuh-archives-*` within 15 minutes, including the full source of the automation app's watchdog scripts as Task Scheduler ran them.
- A harmless script block produces no alert, which is correct: Wazuh's PowerShell rules fire on suspicious content. The full event archive is what keeps every script block searchable for 30 days.
- Lesson: an index pattern caches its field list when it is created. `scriptBlockText` was unsearchable in Discover until the `wazuh-archives-*` field list was refreshed.
- Caveat recorded in the script: anything typed into a PowerShell command, including a secret, is now logged.

### 2026-10-01: CIS benchmark baseline and hardening
- Baseline from Wazuh SCA (CIS Microsoft Windows 11 Enterprise v3.0.0, 482 checks): **27.1%**. Triaged all 345 failures into changes worth making on a personal PC and changes accepted with a written reason. Full write-up: [docs/cis-baseline.md](docs/cis-baseline.md).
- `windows/Set-SentinelGridHardening.ps1` (run elevated, saves prior state, `-Revert` restores it): 16 audit subcategories, firewall drop logging, 5-attempt lockout, NTLM and SMB hardening, stricter UAC, LSASS plugin block, AutoPlay/AutoRun off, Print Spooler and UPnP Device Host disabled, Remote Assistance off.
- Result confirmed by Wazuh's own rescan: **37.0%**, 47 checks fixed, 0 regressions, 1 accepted (UEFI-locked LSASS protection; LSASS protection itself was already on).

### 2026-10-01 (afternoon): Power BI pages 2-4
- **Report as code.** Converted the .pbix to a Power BI Project ([powerbi/SentinelGrid.pbip](powerbi/SentinelGrid.pbip)): the model is TMDL and the pages are PBIR JSON, so the definitions live in Git while the data cache (`.pbi/cache.abf`) stays ignored. Removed 16 hidden auto date/time tables. Pages 2-4 and the new tables are generated by [powerbi/tools/](powerbi/tools/); their output is byte-identical to Power BI's own save, so a re-run on an unchanged report leaves Git clean. Every measure was checked with DAX queries against the open model.
- **Before numbers rebuilt from evidence** ([06_posture.sql](warehouse/sql/06_posture.sql)). The daily vulnerability snapshots began after the Firefox removal, but Wazuh had sent a "was solved" alert for each fixed CVE: 406 of them, plus 39 still open, is exactly 445 (Critical 99 to 0). The first CIS scan's per-check alerts (128 passed, 345 failed) rebuild the 27.1% baseline; summary alerts give 33.6%, 36.6%, 37.0%; every section matches [docs/cis-baseline.md](docs/cis-baseline.md). The loader extracts these events on every run.
- **ATT&CK** ([07_attack_coverage.sql](warehouse/sql/07_attack_coverage.sql)): 33 techniques fired here, each with the rule behind most of it and its triage verdict. "Coverage" needs to know which techniques the deployed rules can detect, which only the Wazuh server knows: [wazuh/manager/export_attack_catalog.py](wazuh/manager/export_attack_catalog.py) exports it and [warehouse/load_attack_catalog.py](warehouse/load_attack_catalog.py) loads it.
- **Pipeline health** ([08_pipeline_health.sql](warehouse/sql/08_pipeline_health.sql)): 99.0% loader success over 7 days, alert-to-SQL latency median 6.4 minutes and 95th percentile 14.9 (the 15-minute schedule), warehouse 69 MB of its 100 GB cap.
- Rule descriptions that embed event fields carried Wazuh's doubled backslashes (the same cause as problem 7). The loader now unescapes descriptions; the backfill cleaned 165 alert rows and 5 rules.
- Finding: rule 92217 (577 alerts, mapped to T1570 Lateral Tool Transfer) is installers and updates writing into System32 (SQL Server setup, AMD bug report tool, .NET native image compiler, Gaming Services). Very likely benign; not yet triaged, and the page says so.

### 2026-10-01 (evening): Detection validation and triage

- Took the Hyper-V checkpoint `sentinelgrid-pre-attack-2026-10-01` as the rollback point for attack testing.
- Controlled test: failed SSH logins against the Wazuh server. Wazuh raised rules 5710, 5503 and 5760 (T1110.001) and escalated to level 10 (rule 2502); the alerts were in SQL about 10.5 minutes later. The brute-force correlation rule did not fire because the test stayed under its threshold, which is documented as a gap. See [the report](triage/2026-10-01-ssh-failed-logins-wazuh-server.md).
- Traced every Critical alert since tuning (51) and every rule 92217 alert (577) to a named process. The AMD cluster turned up repeated graphics driver crashes on the host; the `Add-Type` cluster was the build tooling and stays at Critical on purpose. See [the report](triage/2026-10-01-rules-92213-92217-after-tuning.md).
- Baseline review of the 28 remaining rules behind fired techniques: 27 benign with a named source (Wazuh's own CIS checks, Windows state keys, the build tooling, installs), and one low-risk item whose source process is not confirmed (loopback admin-share access). Every fired technique on the ATT&CK page now carries a verdict. See [the report](triage/2026-10-01-baseline-review-remaining-rules.md).
- Case log: `sg.cases`, `sg.case_rules` and `sg.case_events`, managed with `warehouse/cases.py` (open, assign, note, close). Seeded with the six investigations and one open case split out of the baseline review. A fifth Power BI page, Cases, shows owner, verdict and hours from first alert to verdict (median 13.0). This meets the Stage 7 gate: assigning a case persists in SQL with its history, and `rpt.cases` returns case counts without any credentials.
- Triage verdicts are stored in `sg.rule_triage`, so the ATT&CK Coverage page shows each technique's verdict next to its alerts.
- This public copy is generated by a script kept in the private repo: it replaces details of a private automation workload, then fails if any private term survives or if the rewritten monitoring rules stop matching.

## Problems hit and how they were solved

### 1. Wazuh install failed: "No space left on device"
- **Symptom:** The installer got through the indexer, manager and Filebeat, then failed at the dashboard step and rolled everything back.
- **Cause:** Ubuntu's installer uses LVM and, by default, allocates only part of the disk to the root volume, leaving the rest unallocated.
- **Fix:** Grew the root volume into the free space: `sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv` (root went to 47 GB).

### 2. Reinstall blocked: "Port 1515 / 55000 is being used by another process"
- **Cause:** The rollback could not finish because the disk was full, leaving `wazuh-authd` and the Wazuh API (`python3`) running.
- **Fix:** Found the processes with `sudo ss -tlnp`, then killed them by PID.

### 3. Reinstall failed: "wazuh-keystore: No such file or directory"
- **Cause:** The package database still listed `wazuh-manager` as installed even though its files were gone, so the installer skipped laying down files. Removing the package also failed, because its pre-removal script called binaries that no longer existed (exit status 127).
- **Fix:** Deleted the broken maintainer scripts in `/var/lib/dpkg/info/`, force-purged the package, deleted `/var/ossec`, confirmed with `dpkg -l` that nothing was left, rebooted, then reinstalled cleanly.

### 4. SSH stopped working after a VM reboot
- **Cause:** The Default Switch assigned the VM a new IP (172.26.185.55 became 172.26.183.222).
- **Fix:** Used the automatic `wazuh.mshome.net` hostname for SSH, the dashboard, and agent enrollment.

### 5. The loader could not reach the Indexer on port 9200
- **Cause:** The all-in-one install binds the Indexer to `127.0.0.1` inside the VM (`ss -tlnp` showed `[::ffff:127.0.0.1]:9200`), so opening the firewall did nothing.
- **Fix:** Kept the Indexer private and closed 9200 again. The loader opens an SSH tunnel with a dedicated key that the VM restricts to that one port forward. This is safer than re-binding the Indexer to the network.

### 6. TLS failed: "CA cert does not include key usage extension"
- **Cause:** Python 3.13+ enables strict X.509 checks by default, and the Wazuh installer's self-generated root CA has no keyUsage extension.
- **Fix:** Trust only the Wazuh root CA and clear just the `VERIFY_X509_STRICT` flag. Chain and hostname verification stay on, and a deliberate wrong-hostname test is still rejected.

### 7. Windows paths loaded with doubled backslashes
- **Cause:** Wazuh keeps JSON escaping inside Windows eventdata strings (`C:\\Windows`, `\"`).
- **Fix:** The loader unescapes path and command fields, and `warehouse/sql/04_backfill_unescape.sql` cleaned the rows loaded before the fix.

### 8. After a Windows restart, the VM was unreachable and its firewall would have locked the host out
- **Symptom:** After the Defender offline scan rebooted the host, the dashboard and agent ports were down.
- **Cause:** Hyper-V's Default Switch moved from 172.26.176.0/20 to 192.168.160.0/20, and the VM resumed from saved state still holding its old address. Worse, `ufw` only allowed `172.16.0.0/12`, based on the wrong assumption that the Default Switch always uses that range, so even after the VM got a new address the host's traffic would have been blocked, SSH included.
- **Fix:** Restarted the VM, then from the Hyper-V console (which does not depend on the network) allowed the same four ports from `192.168.0.0/16` and `10.0.0.0/8`. Verified from Windows: 22, 443, 1514 and 1515 open; 9200 and 55000 still closed; the loader caught up on 326 alerts queued during the outage. The runbook now allows all three private ranges from the start.
### 9. The documented journald `ignore` option does not exist in this version
- **Symptom:** `wazuh-logcollector -t` warned: `log_format 'journald' does not support 'ignore' option. Option will be ignored.`
- **Cause:** The Wazuh reference says `ignore` applies to every log format except eventchannel; 4.14.8 does not support it for journald.
- **Fix:** Caught by the pre-restart config test, so nothing broke. Switched to journald's supported include `<filter>` with two collectors (see `wazuh/manager/journald-dashboard-ignore.xml`): everything except the dashboard, plus only the dashboard lines worth keeping.

### 10. The Wazuh agent silently undid the new audit policy
- **Symptom:** The hardening script set 16 audit subcategories and read them back as set, but Wazuh's CIS rescan still failed all 16, and `auditpol /get` later showed "No Auditing".
- **Cause:** With FIM `whodata` on, the agent saves the audit policy when it starts and restores that copy when it stops. Restarting the agent after the change put the old policy back.
- **Fix:** Stop the agent, change the audit policy, then start it, so the new policy becomes its restore point.

### 11. Changing the lockout policy reset two audit subcategories
- **Symptom:** With the agent stopped, all 16 verified as set, then Credential Validation and Application Group Management read "No Auditing" seconds later. The only step in between was `net accounts`.
- **Fix:** Apply the lockout policy before the audit policy. All 16 then held and Wazuh scored them as passing. The mechanism inside Windows was not determined; the required order is documented in the script.

### 12. Power BI refused the generated pages: 490 schema issues
- **Cause:** Inside filters and color selectors, a literal must be written `{"Literal": ...}`; the generator wrapped 11 of them in `{"expr": ...}` as formatting properties are. The validator lists every expression type each bad literal could have been, hence 490 issues from 11 values.
- **Fix:** A separate helper for query literals. Power BI's open-time validation, and its "apply external changes" banner, made the loop fast.

### 13. A KPI card showed "7K" instead of 7,450
- **Cause:** In this release the new card visual always abbreviates numbers and offers display units only for its header, not the value.
- **Fix:** A text measure (`FORMAT(..., "#,0")`), the same workaround page 1 already used for its Low count.

### 14. A count of 54 suspicious scripts came back as 0

- Cause: SQL Server's `JSON_VALUE` returns NULL, without an error, when the value is longer than 4,000 characters. PowerShell script blocks often are, so a filter on the script text silently matched nothing.
- Fix: search long fields in the raw JSON (`raw_json LIKE ...`) or read them with `OPENJSON` and an `nvarchar(max)` column. A zero result now gets a sanity check against the total before it goes in a report.

## Open items

### Hardening
- [x] Back up `~/wazuh-install-files.tar` (cluster certificates and original passwords) to a private folder outside the repo with `scp`. Never commit it.
- [x] Rotate the Wazuh `admin` password with `wazuh-passwords-tool.sh` (random, generated on the server) and store it in a password manager.
- [x] Enable `ufw`: deny all inbound by default, allow only 22, 443 and 1514-1515 from `172.16.0.0/12` (the range Hyper-V's Default Switch draws from). Verified from Windows that those ports are reachable and that 9200 (indexer) and 55000 (API) are blocked.
- [x] Take a Hyper-V checkpoint of the hardened VM, named `wazuh-clean`, as the rollback point for attack testing.
- [ ] Apply Ubuntu updates regularly. Stay on 24.04 until Wazuh supports a newer release.
- [ ] Stage 6 will need 55000 and 9200: open them only to the SentinelGrid API host, with a read-only Wazuh account.

### Detection work
- [x] First controlled test: failed SSH logins against the Wazuh server, detected as T1110.001 and written up ([report](triage/2026-10-01-ssh-failed-logins-wazuh-server.md)). Wazuh's brute-force rule 5712 needs 8 failures from one IP in 120 seconds, so slow guessing only reaches level 10.
- [ ] Run more controlled attack simulations (for example, Atomic Red Team tests on a throwaway VM) and write a triage report for each one.
- [ ] Record which techniques Wazuh detects and which it misses, to build an ATT&CK coverage map.
- [ ] Tune noisy rules only after a baseline of normal activity exists.

### Posture
- [ ] Update Steam and the ChatGPT app, then recheck Vulnerability Detection.
- [ ] Retire Python 3.11 (or upgrade the packages in it) once nothing depends on it.
- [x] CIS baseline recorded and hardened: 27.1% to 37.0% (docs/cis-baseline.md).
- [ ] Review the remaining Administrative Templates failures in smaller batches; test Credential Guard and SmartScreen prevent-bypass.

### Detection tuning
- [x] Deployed `wazuh/rules/sentinelgrid_tuning.xml` (rules 100100 and 100101) after replaying them against 674 stored alerts: every watchdog and sdbinst event matched, every installer event still fired. Live check: the last watchdog alert at level 15 was 19:22:03; from 19:22:53 the same activity arrives as rule 100100 at level 3, with zero new 92213 alerts.
- [x] Confirmed rule 100101 live: 21 matches at level 3 since 2026-09-30 23:53, no new 92058 alerts.
- [x] Traced all 51 Critical (92213) alerts since tuning: AMD Bug Report Tool after graphics driver crashes, PowerShell `Add-Type` compiles by the build tooling (left at Critical on purpose), one Windows troubleshooter ([report](triage/2026-10-01-rules-92213-92217-after-tuning.md)). Host finding: update the AMD graphics driver.

### Archive volume
- [x] Filtered the dashboard's own web logs out of the archive (logins and denied requests kept).
- [ ] Measure archive growth per day after a full day of data.

### Platform
- [x] Stage 8: Power BI pages 2-4 on the `rpt` views (Endpoint Posture, ATT&CK Coverage, Pipeline Health).
- [x] Loaded the ATT&CK catalog from the Wazuh server (v4.14.8: 750 techniques, 1,062 rules with mappings). Of 447 Windows and Linux techniques, 115 (26%) have a deployed rule whose data source is collected here, 33 have fired, and 34 have a rule but no data source here. Rules are classified by an explicit list of collected rule files, and the loader fails if any rule that fired here is classified as not collected (it caught `0955-WEF-baseline_rules.xml` on the first run). Pattern matching had misfiled `mailscanner` and `netscaler` as SCA.
- [x] Layout: moved height from the middle row to the bottom row and shrank the CIS section labels so the first-scan and current labels no longer collide.
- [x] Screenshots of pages 2-4 in `docs/screenshots` and the README.
- [x] Rebuilt page 1 (SOC Overview) in the same design: severity colors, Critical and High triage table, and a "tuning in action" chart showing rule 92213's watchdog noise moving from Critical to Low the hour rule 100100 went live. All four pages are now generated.
- [x] Least-privilege reporting access (`10_reporting_access.sql`). SQL Server stays in Windows-authentication-only mode, Microsoft's recommended setting, so no SQL password exists to steal; switching to mixed mode just to add a password login would weaken that. Instead, a login-less `powerbi_reader` user in the `rpt_reader` role was tested with `EXECUTE AS`: reading `rpt.cases` is allowed; reading `sg.alerts`, updating `sg.cases` and deleting from `sg.case_events` are all denied (error 229). Power BI on this one-person lab still signs in as the analyst; a shared deployment would add its own Windows or Entra identity to the role.
- [x] Triaged rule 92217: all 577 Low alerts are software installs and updates (same report).
- [ ] Delete `PowerBI-SOC.pbix` once the project is confirmed as the only copy (it is superseded and git-ignored).
- [ ] Stage 6: build the SentinelGrid API with a read-only Wazuh account and switch the console from demo data to live alerts.
