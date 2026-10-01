# Event Trace: One Process Launch, Followed Through Every Layer

Runbook Stage 4 asks for proof that a single, deliberately created event can be traced from the Windows endpoint all the way to the analyst's screen. This trace follows one `whoami` execution from Sysmon to Wazuh to the Indexer, then on into the SQL warehouse and Power BI.

## The test

On 2026-09-30 at 9:22 PM Eastern (2026-10-01 01:22 UTC), harmless activity was generated on `jordan-pc`:

```powershell
cmd.exe /c "echo SG-TRACE-001 & whoami /user"   # the traced event
notepad.exe                                     # a benign process launch
nslookup example.com                            # a DNS lookup
```

`whoami` was chosen because attackers commonly run it right after gaining access, to learn which account they control (MITRE ATT&CK T1033 and T1087). Running it inside `cmd.exe` with the tag `SG-TRACE-001` puts the tag in the parent command line, so this exact event can be found among thousands.

## The traced event, hop by hop

| # | Layer | Evidence | Key values |
|---|---|---|---|
| 1 | **Windows / Sysmon** | Local `Microsoft-Windows-Sysmon/Operational` log, read before Wazuh was consulted | Event ID **1** (process create), UtcTime `2026-10-01 01:22:09.396`, PID 432, `C:\Windows\System32\whoami.exe` with `whoami /user`, parent `cmd.exe /c "echo SG-TRACE-001 & whoami /user"`, user `WIN11-HOST\Jordan`, SHA-256 `23240EF9F8B0A9A324110B1C2331DE31DC1B0E08F5359CB707E51A939AF56CD3` |
| 2 | **Wazuh agent** | `location: EventChannel`, channel `Microsoft-Windows-Sysmon/Operational` | Collected through the `default` group's centrally managed `agent.conf`. Same Windows record: `eventRecordID` **44012**, `processGuid` `{e736f507-b5c1-6abd-fb58-00000000b600}` |
| 3 | **Wazuh manager** | Decoder `windows_eventchannel`, matched rule **92032** | "Suspicious Windows cmd shell execution", level 3, MITRE **T1087** (Account Discovery) and **T1059.003** (Windows Command Shell), tactics Discovery and Execution. Alert ID `1790817729.566266`, timestamp `01:22:09.896`, about **0.5 seconds** after Sysmon recorded the process. |
| 4 | **Wazuh Indexer** | Searched as the read-only `sentinelgrid_loader` user | Index `wazuh-alerts-4.x-2026.10.01`, document `_id` **`MWsO9aABUbyB79YaBASQ`** |
| 5 | **Wazuh dashboard** | Threat Hunting search (see [Dashboard verification](#dashboard-verification)) | Same alert, shown to the analyst |
| 6 | **SQL warehouse** | `sg.alerts` row keyed by the Indexer `_id` | `doc_id = MWsO9aABUbyB79YaBASQ`, `win_event_id = 1`, `rule_id = 92032`, loaded at `01:23:13` UTC (about **64 seconds** after the event). Bridge rows: techniques T1087 and T1059.003; tactics Discovery and Execution. |
| 7 | **Reporting view / Power BI** | `rpt.alerts` | `alert_time_local = 2026-09-30 21:22:10`, `severity_band = Low`, `agent_name = jordan-pc`. Counted in the Power BI **Low** card after a refresh. |

**Correlation keys that tie the layers together:** the Windows `EventRecordID` (44012) and Sysmon `ProcessGuid` link the endpoint to the Wazuh alert, and the Indexer document `_id` links the Wazuh alert to the SQL row and everything built on it.

## The rest of the process tree

| Process | Sysmon event | Wazuh alert |
|---|---|---|
| `cmd.exe /c "echo SG-TRACE-001 & whoami /user"` | ID 1, record 44011 | Rule 92004, level 4: "Powershell process spawned Windows command shell instance" (T1059.003) |
| `whoami.exe /user` | ID 1, record 44012 | **Rule 92032, level 3** (the traced event above) |
| `notepad.exe` | ID 1, recorded locally | **None** |
| `nslookup example.com` | No DNS event (ID 22) found | **None** |

## What the trace showed

1. **The pipeline works end to end, and fast.** Endpoint to SIEM alert in about half a second. Endpoint to SQL in about a minute, bounded by the loader schedule.
2. **Wazuh stores alerts, not every event.** Notepad's launch exists in the local Sysmon log but nowhere in Wazuh, because no rule matched it. This is the gap the runbook's raw-event warning describes, and it is why the parent process behind the watchdog noise had to be found live during [the second triage](../triage/2026-09-30-rule-92213-powershell-policy-test-noise.md). **Closed on 2026-10-01:** full event archiving (`wazuh-archives-*`) was enabled with a 30-day retention policy. Notepad launches at 05:22:37 and 05:27:36 UTC now appear in Wazuh as Sysmon event ID 1 (records 61465 and 61778), with the same SHA-256 recorded locally above, even though no rule alerts on them.
3. **`nslookup` is a DNS blind spot.** Sysmon's DNS event (ID 22) comes from the Windows DNS Client, and `nslookup` sends its queries directly to the DNS server, bypassing that client. Lookups made through normal applications and `Resolve-DnsName` go through the DNS Client and are visible to Sysmon. Network-level DNS visibility is one of the reasons for Suricata (Stage 5).
4. **Severity reflects context.** `whoami` alone is rated level 3 (Low): common for admins, but worth recording, because in a real intrusion it is often among the first commands an attacker runs.

## Dashboard verification

Completed in the Wazuh dashboard by the analyst:

- [ ] **Threat Hunting:** search `_id:MWsO9aABUbyB79YaBASQ` (time range covering 2026-09-30 9:20 to 9:25 PM) and confirm rule 92032 on `jordan-pc`.
- [x] **Indexer management > Dev Tools:** `GET _cat/indices/wazuh-*?v` returned 18 indices, all **green**. Daily alert indices: `wazuh-alerts-4.x-2026.09.30` (3,382 documents, 7 MB) and `wazuh-alerts-4.x-2026.10.01` (356 documents so far). `wazuh-states-vulnerabilities-wazuh` held 39 documents, matching the SQL warehouse's vulnerability snapshot.

A side observation from Threat Hunting: each loader run appears on the Wazuh server itself as `sshd: authentication success` (rule 5715) followed by a PAM session open and close. The SOC records its own data pipeline connecting.
