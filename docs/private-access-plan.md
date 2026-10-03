# Private Remote Access: Tailscale Plan

**Owner:** Jordan Carven-Bellace

**Updated:** October 3, 2026

**Status:** setup started; device enrollment, policy enforcement and connection tests are not yet verified. All implementation gates below remain open.

## Decision and purpose

Add Tailscale to the trusted admin device and the Ubuntu Wazuh VM so the lab can be administered from another network without forwarding management ports through the home router. This is the next security engineering exercise for Watchtide: define who needs access, restrict that access, prove both successful and blocked connections, and document the effect on the monitoring pipeline.

The existing documented baseline is a Hyper-V NAT lab, an indexer bound to loopback, a restricted SSH tunnel for the loader, and local SQL/Power BI reporting. The VPN adds a private route; it does not establish that every service is correctly restricted. Tailscale encrypts device traffic with [WireGuard](https://tailscale.com/docs/concepts/tailscale-encryption).

## Public portfolio and private lab

```text
Employers -> GitHub README, runbook, cases and roadmap
          -> GitHub Pages console -> sanitized snapshot only

Approved admin device -> Tailscale -> Ubuntu VM: SSH / Wazuh dashboard
Remote test endpoint  -> Tailscale -> Wazuh manager: event ingestion (later)

Existing local path:
Windows + Sysmon -> Wazuh agent -> manager -> indexer
Windows loader   -> restricted SSH tunnel -> loopback indexer -> SQL -> Power BI
```

Employers can review the public artifacts without lab credentials or a tailnet invitation. Any later live analyst console/API stays private. No Tailscale Funnel is planned for SOC services: [Funnel publishes a selected service to the internet](https://tailscale.com/docs/features/tailscale-funnel).

An exit node and subnet router are deferred. The first exercise only needs device-to-device access; [exit nodes](https://tailscale.com/docs/features/exit-nodes) route general internet traffic and are a separate decision.

## Intended access matrix

These are proposed permissions, not a record of deployed rules. Verify configured service ports before applying them; Wazuh defaults are listed in its [architecture documentation](https://documentation.wazuh.com/current/getting-started/architecture.html).

| Source | Destination | Intended access | Restriction |
|---|---|---|---|
| Approved admin devices | Ubuntu SOC VM | TCP 22 (OpenSSH), TCP 443 (dashboard) | Explicit device selection; retain application login and TLS verification |
| Remote monitored endpoint | Wazuh manager | TCP 1514 (events) | Ingestion only; no SSH, dashboard, SQL, indexer or API privileges |
| Approved enrolling endpoint | Wazuh manager | TCP 1515 (enrollment) | Temporary enrollment window; remove permission and test after registration |
| Existing local loader | Ubuntu SOC VM | Current restricted SSH tunnel | Preserve its no-shell key and loopback-only port forward; verify each scheduled load |
| Wazuh dashboard / local collector | Indexer and Wazuh API | Existing internal access | TCP 9200 remains on loopback; TCP 55000 is not exposed to remote endpoints |
| Power BI Desktop on Windows | Local SQL warehouse | Existing authenticated reporting path | No new remote SQL listener or inbound port rule needed for this milestone |
| Other tailnet devices / public internet | SOC management and data services | Denied | Test denied access independently of successful admin access |

Use [Tailscale grants](https://tailscale.com/docs/features/access-control/grants) for a new policy. Inspect the current policy for broad permissions before narrowing it. A user-group rule can authorize several devices owned by that user; choose selectors that actually enforce the intended device restriction. Limit who can assign privileged device tags, and include policy tests for approved and unprivileged sources.

Tailscale policy and the operating-system firewall control different paths. Review their effective behavior together; do not infer tailnet restrictions solely from `ufw status`. Preserve only the local agent/loader exceptions the lab needs. The [Ubuntu firewall guide](https://tailscale.com/docs/how-to/secure-ubuntu-server-with-ufw) describes restricting non-Tailscale access and testing from outside the private network.

## Implementation sequence

1. Record current agent status, a successful scheduled load and reporting freshness. Save firewall rules, service listeners and the existing tailnet policy outside Git. Take a Hyper-V checkpoint and verify VM-console access for recovery.
2. Install/enroll Tailscale on the trusted admin device and inside Ubuntu. Enrolling the Windows Hyper-V host alone does not enroll its guest. Verify both device identities privately; enable MFA at the sign-in provider and review device/key-expiry settings.
3. Confirm routing and the intended SSH/dashboard ports. Keep ordinary OpenSSH and the existing restricted loader key for this milestone; adopting Tailscale SSH would require a separate review of that tunnel restriction. Resolve dashboard hostname/certificate trust before using its tailnet address; do not disable certificate checking to make the test pass.
4. Define the narrow grants in the matrix and test them. Keep a working VM-console session while changing access. Remove broad management exceptions only after the private route and necessary local loader access both work.
5. From another network, test successful admin access and failed access from an unprivileged tailnet test device. Also test direct public access with Tailscale off, review router forwarding and any public publishing settings, and record any limits of the external test, including unavailable IPv6.
6. Wait for the next scheduled load and verify the local agent remains Active, new alerts reach SQL, and Power BI can refresh. A working dashboard alone does not prove the pipeline survived the change.
7. Publish redacted results, update the build log, and only then mark the private-access milestone complete. Add a remote monitored endpoint as a separate exercise after the policy is validated.

## Completion and evidence

For every test, record the date, source role, destination/service, expected result, actual result and a sanitized screenshot or log excerpt. Keep real addresses, device identities and raw output in private notes. A failed prerequisite leaves its dependent gate open.

| Gate | Required evidence | Status |
|---|---|---|
| Admin device and Ubuntu VM enrolled | Correct devices verified in private inventory | Pending |
| Approved admin access off-LAN | Successful SSH login and dashboard login with verified HTTPS identity | Pending |
| Unprivileged tailnet device denied | TCP 22/443 connection attempts fail from a device without admin permission | Pending |
| No direct public service access | External checks for TCP 22/443/1514/1515/9200/55000 fail; forwarding/publishing reviewed; IPv4/IPv6 scope recorded | Pending |
| Internal data services remain restricted | Direct TCP 9200/55000 access fails from remote test devices; loader tunnel still works | Pending |
| Existing collection/reporting stays healthy | Local agent Active, successful scheduled load, new event in SQL, Power BI refresh | Pending |
| Device revocation works | Remove a disposable test device and confirm it loses private service access | Pending |
| Public documentation is sanitized | Access matrix and test outcomes published without credentials or private inventory | Pending |

Keep this status honest: installing a client is a setup step; passing these tests is the evidence for the control.

## Next exercise: remote collection

- [ ] Enroll one authorized test endpoint on a separate network with TCP 1515 allowed only for enrollment.
- [ ] Remove its enrollment permission, retain TCP 1514, and confirm ingestion continues.
- [ ] Generate one harmless event covered by the endpoint's logging and Wazuh rules.
- [ ] Trace its timestamp, rule and document identifier through Wazuh, SQL and Power BI; record reporting latency.
- [ ] Verify that endpoint cannot reach management/data services, and that a repeated enrollment connection is denied.
- [ ] Publish a sanitized event trace with any observed gap or unexpected result.

## Monitoring and reporting implications

Endpoint logging remains essential: encrypted VPN packets do not provide a LAN sensor with their inner contents. The Suricata chapter must identify its capture point and test what it can actually observe. Review available sign-in, device and policy-change records; confirm Tailscale plan availability before promising audit-log export or SIEM ingestion.

Power BI Desktop still uses the existing local SQL connection. If cloud refresh is added later, the Power BI service needs a supported route to private SQL, usually an [on-premises data gateway](https://learn.microsoft.com/en-us/power-bi/connect-data/service-gateway-onprem); installing Tailscale on a laptop does not give Microsoft's service a tailnet identity.

## Recovery and publication

If access fails, use the Hyper-V console to restore the saved policy/firewall exceptions. Recheck the local agent and loader before retrying. Keep the checkpoint as a recovery option for VM changes; it does not restore tailnet policy or Windows/SQL state. Revoke a lost or disposable device promptly.

Publish the design, test outcomes, sanitized policy examples and reporting screenshots. Keep credentials, auth keys, private keys, real device inventory, raw logs and private backups outside the public repo. If a published credential is discovered, revoke or rotate it; deleting the current file alone does not remove Git history. Use Watchtide's existing sanitized publishing process and review screenshots separately.

Until the gates pass, portfolio wording is: "Tailscale private remote access is in progress, with least-privilege policy and end-to-end validation planned." After validation, replace that sentence with measured results and link the test report.
