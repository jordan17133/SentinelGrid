# Finding: A Forgotten Browser Held Every Critical Vulnerability

| Field | Value |
|---|---|
| Date | 2026-09-30 |
| Analyst | Jordan Carven-Bellace |
| Host | jordan-pc |
| Source | Wazuh Vulnerability Detection (first scan of the endpoint) |
| Software | Mozilla Firefox 146.0, plus the Mozilla Maintenance Service |
| Impact | 393 of 445 findings (88%), including **all 99 Critical** and 226 High; highest CVSS score 10.0 |
| Action | Uninstalled Firefox and the Mozilla Maintenance Service |
| Result | Critical findings 99 to 0 |

## What was found

The first vulnerability scan of the workstation reported 445 findings, 99 of them Critical. Grouping them by package in the SQL warehouse showed one source for most of them: Firefox 146.0, a version that had not been updated because the browser had not been opened since December 2025. Every Critical finding on the machine belonged to it.

Its updater, the Mozilla Maintenance Service, was still installed. That is a Windows service that runs with system-level privileges so it can update Firefox without asking the user, which makes it part of the attack surface even when the browser itself is never opened.

No malware or sign of compromise was found; this is a vulnerability and attack-surface finding, not an incident.

## Why it matters

- **Unused is not the same as safe.** Vulnerable code that is still installed can be reached: by a file or link handed to it, by another program calling it, or through its privileged service.
- **Forgotten software stops getting patched.** Browsers update themselves when they run; one that never runs falls further behind every month.
- **One package can dominate the risk.** Sorting findings by package, rather than working through 445 individual CVEs, pointed straight at the fix with the biggest effect.

## Action and verification

1. Confirmed the browser was unused and nothing depended on it.
2. Uninstalled Firefox and the Mozilla Maintenance Service. The removal itself showed up in the SIEM: the uninstaller's files triggered rule 92213 (see [the second triage report](../triage/2026-09-30-rule-92213-powershell-policy-test-noise.md)), and file integrity monitoring recorded the service's registry keys being deleted (rule 751, see [the baseline review](../triage/2026-10-01-baseline-review-remaining-rules.md)).
3. The next scan confirmed every Firefox finding as resolved, and Critical findings went from 99 to 0. Each resolved finding is backed by a Wazuh "solved" alert in the warehouse (`rpt.vulnerability_findings`).

## Related

The same principle drove a later change: an outdated Python 3.11 was retired, but only after a workload that depended on it was migrated, because unlike the browser, something still needed it. See the build log entry for 2026-10-02.
