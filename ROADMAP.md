# Watchtide Roadmap

What is built, what comes next, and why. Each chapter ends the same way: build it, test it, write it up as a case or report, then publish.

## Done

- [x] Lab: Hyper-V VM, Ubuntu Server 24.04, Wazuh 4.14 all-in-one, hardened (firewall, rotated credentials, backups, checkpoints)
- [x] Endpoint telemetry: Sysmon, Windows Security and System logs, Microsoft Defender, PowerShell script-block logging, file integrity monitoring with who-did-it attribution
- [x] One event traced through every layer ([docs/event-trace.md](docs/event-trace.md))
- [x] Posture: 437 of 447 vulnerability findings resolved (10 open, zero Critical); CIS Benchmark 27.1% to 37.0% ([docs/cis-baseline.md](docs/cis-baseline.md))
- [x] Detection tuning with tested custom rules (100100, 100101) and FIM severity rules (100110-100113)
- [x] SQL Server warehouse with a scheduled loader (every 15 minutes, 99% success) and data lifecycle rules
- [x] Case log with history; nine investigations closed, one open ([triage/](triage/))
- [x] Every fired MITRE ATT&CK technique triaged to a verdict
- [x] First controlled attack test: SSH password guessing, detected end to end
- [x] Least-privilege reporting role, tested
- [x] Five Power BI dashboards kept as code in Git
- [x] Public read-only SOC console on a scrubbed snapshot ([console](https://jordan17133.github.io/Watchtide/))

## Next, in order

| # | Chapter | Why it matters | Done when |
|---|---|---|---|
| 1 | **Attack simulations, round 2** on a separate test VM (Atomic Red Team) | Turns "a rule exists" into "a rule is proven" | 5+ techniques validated, each with a case; a "validated by test" status on the ATT&CK page |
| 2 | **Close SG-007** (loopback admin-share access) | Finish the open case | Detailed File Share auditing (event 5145) names the process; case closed |
| 3 | **Phishing analysis** | The most common Tier 1 task | 2+ sample emails analyzed (headers, links, attachments) and written up as cases |
| 4 | **Threat intel enrichment** | Faster, better verdicts | Case write-ups check hashes, IPs and domains against public reputation sources |
| 5 | **Second SIEM: Splunk** | Most SOC job posts name Splunk or Sentinel | Same logs searched in Splunk; Boss of the SOC practice questions solved |
| 6 | **Architecture diagram and demo video** | A 2-minute way in for busy reviewers | Diagram in the README; video showing alert to case to dashboard |
| 7 | **Active Directory lab** | Most companies run Windows domains | Small domain in Hyper-V; common AD attacks detected and written up |
| 8 | **EDR** (Microsoft Defender for Endpoint trial) | Endpoint detection and response is standard in SOCs | Defender alerts correlated with Wazuh in a case |
| 9 | **Network monitoring: Suricata** (runbook Stage 5) | Today the lab is endpoint-only | DNS and HTTP events visible and traced to Wazuh records |
| 10 | **Live API behind the console** (runbook Stage 6, second part) | Work cases from the console, not a script | Analysts open, assign and close cases from the web console |
| 11 | **Alert notifications** for level 12 and above | Faster response | Optional; tested so it never floods |

## Ongoing upkeep

- Weekly: check Pipeline Health (loader success above 95%, data fresh within 30 minutes) and patch the VM.
- Before risky work: take a Hyper-V checkpoint.
- After a Wazuh upgrade: re-export the ATT&CK catalog and reload it.
- After any new case: refresh the console snapshot.
