# SentinelGrid SOC Platform Build Runbook

This runbook builds SentinelGrid in layers so that every alert can be traced back to a real source. Commands and product versions were checked on September 29, 2026, and revised on September 30, 2026 after the first build. When a vendor page shows a newer minor release, use the command or package shown on that vendor page.

What actually happened during the build, including every failure and fix, is recorded in [BUILD-LOG.md](BUILD-LOG.md).

## Progress

| Stage | Status |
|---|---|
| 0. Prepare the lab | Done 2026-09-30 |
| 1. Wazuh all-in-one stack | Done and hardened 2026-09-30 |
| 2. Sysmon | Done 2026-09-30 |
| 3. Windows Wazuh agent | Done 2026-09-30 |
| 4. First real event path | Done 2026-09-30 |
| 4b. Review posture findings | Done 2026-10-01 (445 findings cut to 39, CIS 27.1% to 37.0%) |
| 7. SQL Server warehouse (moved ahead of Stage 6) | Done 2026-09-30; case log added 2026-10-01 (`warehouse/cases.py`) |
| 8. Power BI report | Done 2026-10-01 (five pages including Cases, kept as a Power BI Project in Git) |
| Detection validation | In progress: controlled SSH password-guessing test detected and written up |
| 6. SentinelGrid API | Planned |
| 5. Suricata network telemetry | Planned |

## Lab facts

| Item | Value |
|---|---|
| Wazuh VM | Hyper-V `SentinelGrid-Wazuh`, Ubuntu Server 24.04.5, 4 vCPU, 8 GB fixed RAM, 150 GB disk, Default Switch |
| Wazuh version | 4.14.8 all-in-one |
| Address | `wazuh.mshome.net` (never the raw IP; it changes on VM reboot) |
| Dashboard | `https://wazuh.mshome.net` |
| SSH | `ssh <ubuntu-user>@wazuh.mshome.net` |
| Monitored endpoint | `jordan-pc` (Windows 11, Sysmon64 + Wazuh agent) |
| Rollback point | Hyper-V checkpoint `sentinelgrid-pre-attack-2026-10-01` (the earlier `wazuh-clean` was merged when the disk grew) |
| Open VM ports | 22, 443, 1514-1515 from private ranges only (10/8, 172.16/12, 192.168/16) |

## Target architecture

```text
Windows endpoint
  Sysmon -> Windows Event Log -> Wazuh Agent
                                      |
                                      v
Ubuntu Server VM
  Wazuh Server -> Filebeat -> Wazuh Indexer
       |                            |
       +-> Wazuh Dashboard         +-> Python loader (read-only account, every 15 min)
                                   |          |
                                   |          v
                                   |   SQL Server warehouse -> Power BI
                                   |          ^
                                   +-> SentinelGrid API ----+  (later: incidents, analyst actions)
                                              |
                                              v
                                      SentinelGrid Console

Later: Suricata -> eve.json -> Wazuh Agent -> Wazuh Server
```

The first build loads SQL Server directly from the Wazuh Indexer with a small Python loader, so Power BI gets real data before the SentinelGrid API exists. When the API is built, it writes incident and analyst-action data into the same warehouse.

## Stage 0: Prepare the lab

### Programs and documentation

- [Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server)
- [Enable Hyper-V on Windows 11](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v?pivots=windows&tabs=gui)
- [Oracle VirtualBox downloads](https://www.virtualbox.org/wiki/Downloads) if Hyper-V is unavailable
- [Wazuh Quickstart](https://documentation.wazuh.com/current/quickstart.html)

### Steps

1. Pick one Windows computer to monitor. Do not begin with every personal device.
2. Create an Ubuntu Server 24.04 LTS VM using Hyper-V or VirtualBox.
3. Allocate the Wazuh-recommended minimum for 1-25 agents: 4 vCPU, 8 GiB RAM, and 50 GB storage.
4. Configure the VM network so the Windows endpoint can reach the VM, but do not configure router port forwarding. This lab uses Hyper-V's Default Switch (NAT, reachable only from the host). On Hyper-V, `Enable-SentinelGridHyperV.ps1` and `Create-SentinelGridWazuhVM.ps1` do steps 2 to 4; a reboot is required after enabling Hyper-V.
5. Install Ubuntu, create a non-root administrator account, enable the OpenSSH server, and install security updates. Name the server `wazuh`.
6. **Give Ubuntu the whole disk.** The Ubuntu installer's default LVM layout leaves roughly half the disk unallocated, which makes the Wazuh install fail with "No space left on device." Check and fix before installing anything:

```bash
df -h /
sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
```

7. Record the VM's address with `ip -brief address`. On the Default Switch this IP changes whenever the VM reboots, so use the hostname `wazuh.mshome.net` (the server name plus `.mshome.net`) everywhere instead.
8. Create a VM checkpoint named `ubuntu-clean`.

### Completion gate

From Windows, `Test-NetConnection wazuh.mshome.net -Port 22` must succeed. Ping may fail; that is expected.

## Stage 1: Install the all-in-one Wazuh stack

Wazuh's all-in-one installation includes the Wazuh Server, Filebeat, Wazuh Indexer, and Wazuh Dashboard. Do not install a separate OpenSearch server for this lab.

### Steps on Ubuntu

1. Update Ubuntu:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install curl -y
```

2. Run the current Wazuh installation assistant. The current documentation uses the 4.14 channel:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

3. Save the generated administrator credentials in a password manager. Do not paste them into source code, screenshots, Git, or chat messages.
4. Verify the services:

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
sudo systemctl status filebeat --no-pager
```

5. From Windows, open `https://wazuh.mshome.net` and sign in. A certificate warning is expected with the initial self-signed lab certificate.
6. Back up the install secrets. `~/wazuh-install-files.tar` holds the cluster certificates and original passwords. It is owned by root, so take ownership, then copy it from Windows to a private folder outside the repo:

```bash
sudo chown <ubuntu-user> ~/wazuh-install-files.tar
```

```powershell
scp <ubuntu-user>@wazuh.mshome.net:~/wazuh-install-files.tar "$HOME\Documents\SentinelGrid-Private\"
```

7. Rotate the `admin` password. Omitting `-p` makes the tool generate a random password, so it is never typed into shell history. The tool updates Filebeat and the dashboard automatically on an all-in-one install:

```bash
sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin
```

8. Enable the firewall. Allow only what the lab needs, from the private ranges. The Default Switch can move to a different private range (172.16.0.0/12 **or** 192.168.0.0/16 have both been observed here) after a Windows restart, so allow all three RFC 1918 ranges; the switch is NAT-only, so none of them are reachable from outside the host. TCP 9200 (indexer) and 55000 (API) stay closed:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
for n in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do sudo ufw allow from $n to any port 22,443,1514,1515 proto tcp; done
sudo ufw enable
```

9. Verify from Windows that 22, 443, 1514 and 1515 are reachable and 9200 and 55000 are not, then create a VM checkpoint named `wazuh-clean`:

```powershell
Checkpoint-VM -Name SentinelGrid-Wazuh -SnapshotName "wazuh-clean"
```

### If the install fails partway

The installer rolls back on failure, but if the rollback itself fails (for example because the disk is full), leftovers block the next attempt with "Port 1515/55000 is being used" or "wazuh-keystore: No such file or directory." Clean up fully, then reinstall with `-a -o`:

```bash
sudo systemctl stop wazuh-manager; sudo pkill -f /var/ossec
sudo rm -f /var/lib/dpkg/info/wazuh-manager.prerm /var/lib/dpkg/info/wazuh-manager.postrm
sudo dpkg --purge --force-all wazuh-manager
sudo rm -rf /var/ossec
dpkg -l | grep -E 'wazuh|filebeat'   # must print nothing
sudo reboot
# after reconnecting:
sudo ss -tlnp | grep -E ':1515|:55000'   # must print nothing
sudo bash ./wazuh-install.sh -a -o
```

### Completion gate

All four services must be active, the Wazuh Dashboard must load, and Indexer Management must show a healthy single-node indexer.

## Stage 2: Install and verify Sysmon

### Documentation

- [Enable and configure built-in Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)

### Steps on Windows as Administrator

1. Check whether Sysmon already exists:

```powershell
Get-Service Sysmon*
```

2. If standalone Sysmon is already installed, do not also enable built-in Sysmon. Microsoft does not support running both together.
3. If Sysmon is not installed and built-in Sysmon is supported, enable it:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Sysmon
```

4. Create or download a reviewed Sysmon configuration. Microsoft's guide links to maintained community configurations and includes a small example. This lab uses standalone Sysmon64 (kept in the git-ignored `tools/` folder) with the [SwiftOnSecurity configuration](https://github.com/SwiftOnSecurity/sysmon-config):

```powershell
cd C:\Users\Jordan\Desktop\SIEM-SOC\tools
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

5. Or, for built-in Sysmon, install or apply the configuration:

```powershell
sysmon -i C:\Sysmon\sysmonconfig.xml
```

If Sysmon was already initialized, update it instead:

```powershell
sysmon -c C:\Sysmon\sysmonconfig.xml
```

6. Open Event Viewer and navigate to `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.
7. Start Notepad and run `nslookup example.com`; confirm new process and DNS/network events appear.

### Completion gate

Sysmon events must be visible locally before Wazuh is introduced. Sysmon records evidence; it does not create alerts or block activity.

## Stage 3: Install and enroll the Windows Wazuh agent

### Documentation

- [Deploy a Wazuh agent on Windows](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Wazuh agent enrollment](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html)
- [Collect Windows event channels](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)

### Steps

1. In Wazuh Dashboard, open `Agents management > Summary > Deploy new agent`.
2. Select Windows (MSI 32/64 bits), enter `wazuh.mshome.net` as the Wazuh Server, name the agent, and copy the generated installation command.
3. Run that generated command in an elevated Windows PowerShell window.
4. Start the agent:

```powershell
Start-Service WazuhSvc
```

The agent shows `Pending` for a minute or two before it turns `Active`.

5. Collect Sysmon centrally rather than editing each endpoint. In the dashboard, open `Agents management > Groups > default`, edit `agent.conf`, and set:

```xml
<agent_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

Every agent in the `default` group receives this automatically. (Editing `C:\Program Files (x86)\ossec-agent\ossec.conf` on the endpoint also works, but does not scale.)

6. Restart the agent so it picks up the change immediately:

```powershell
Restart-Service WazuhSvc
```

7. Return to Wazuh Dashboard and confirm the agent is `Active`, then search Threat Hunting for `data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"`.

### Completion gate

The Windows endpoint must appear as an active agent. The endpoint must be able to reach the Wazuh VM on TCP 1514, and TCP 1515 must be available during enrollment.

## Stage 4: Prove the first real event path

### Steps

1. On Windows, produce harmless activity:

```powershell
notepad.exe
whoami /all
nslookup example.com
powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"
```

2. Confirm the activity first in the local Sysmon Operational log.
3. In Wazuh Dashboard, filter security events by the Windows agent name and inspect the newest records.
4. In `Indexer management > Dev Tools`, list Wazuh indices:

```http
GET /_cat/indices/wazuh-*?v
```

5. Record one event's timestamp, agent name, Windows event ID, process, parent process, user, and Wazuh rule.
6. Do not enable automated blocking or endpoint isolation yet.

### Raw-event warning

Wazuh indexes alerts by default. Harmless Sysmon activity may not trigger an alert. Full threat hunting requires `wazuh-archives-*`, which stores far more data. Read the [Wazuh event archiving guide](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html) and set a retention plan before enabling archives broadly.

### Full event archive with retention (enabled 2026-10-01)

Do the retention pieces first so nothing grows unbounded.

1. **Room to grow.** Expand the VM disk (here 50 GB to 150 GB). Hyper-V cannot resize a disk with checkpoints, so the script merges them when asked. Take a new checkpoint at the end.

```powershell
.\Grow-SentinelGridVMDisk.ps1 -RemoveCheckpoints   # elevated
```

```bash
lsblk                                   # sda should show the new size
sudo growpart /dev/sda 3
sudo pvresize /dev/sda3 && sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
df -h /
```

2. **Recycle the raw rotated logs.** Wazuh compresses its raw logs daily but never deletes them. Install [wazuh/retention/sentinelgrid-retention.cron](wazuh/retention/sentinelgrid-retention.cron) as `/etc/cron.d/sentinelgrid-retention` (no dot in the name, or cron ignores it): archives 7 days, alerts 90 days.
3. **Turn on archiving** on the manager and shipping in Filebeat, backing up both files first:

```bash
sudo sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf
sudo sed -i '/archives:/{n;s/enabled: false/enabled: true/}' /etc/filebeat/filebeat.yml
sudo systemctl restart wazuh-manager filebeat && sudo filebeat test output
```

4. **Recycle the searchable copies.** Run [wazuh/retention/ism-policies.http](wazuh/retention/ism-policies.http) in Dev Tools: `wazuh-archives-*` deleted after 30 days, `wazuh-alerts-*` after 365, attached automatically to each new daily index via `ism_template`. Confirm with `GET _plugins/_ism/explain/wazuh-a*`.
5. **Make it searchable.** Create the index pattern `wazuh-archives-*` with time field `timestamp`.
6. **Prove it.** Launch Notepad, then search Discover on `wazuh-archives-*` for `agent.name:jordan-pc and data.win.eventdata.image:*otepad.exe`. A Sysmon event ID 1 must appear even though no rule alerts on it.

The SQL warehouse has its own lifecycle in [warehouse/sql/05_lifecycle.sql](warehouse/sql/05_lifecycle.sql): every alert row is kept, Low-severity raw JSON is trimmed after a year, daily summaries per rule and MITRE technique are permanent, and the data file is capped at 100 GB.

### Completion gate

You must be able to trace one record through this chain: activity on Windows -> Sysmon event -> Wazuh agent -> Wazuh Server rule/decoder -> Wazuh Indexer -> Wazuh Dashboard.

Expect a burst of high-severity alerts right after installing Sysmon and the agent; the installers themselves trip rules such as 92213 (level 15). Triage them rather than ignoring them. The first write-up is in [triage/](triage/).

## Stage 4b: Review posture findings

Wazuh scans enrolled agents out of the box. Use it to fix real weaknesses on the endpoint before adding more data sources.

1. Open `Vulnerability Detection` in the dashboard, filter to the agent, and sort by severity. Each finding names the package, installed version, CVE and fixed version.
2. Update or remove the affected software, starting with Critical and High. Findings clear after the next scan.
3. Open `Configuration Assessment` and review the CIS benchmark results for the agent. Fix failed checks that make sense for a personal PC and record the ones deliberately left alone, with the reason.
4. Record before and after counts in the build log.

### Completion gate

No Critical vulnerability findings remain unexplained, and the Configuration Assessment score has a recorded baseline.

## Stage 5: Add Suricata network telemetry

Do this only after Stage 4 works reliably.

### Documentation

- [Suricata documentation](https://docs.suricata.io/en/latest/)
- [Official Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)

### Steps

1. Install Suricata on a Linux sensor VM that can observe the lab traffic.
2. Configure the correct monitoring interface and verify that `/var/log/suricata/eve.json` receives JSON records.
3. Install a Wazuh agent on the sensor.
4. Configure that agent to collect the EVE file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

5. Restart Suricata and the Wazuh agent, then confirm Suricata events appear in Wazuh.

### Completion gate

At least one benign DNS or HTTP connection must be visible in `eve.json` and traceable to a Wazuh record.

## Stage 6: Connect the SentinelGrid API

### Programs and documentation

- [Node.js LTS](https://nodejs.org/en/download)
- [Wazuh Server API guide](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- [Wazuh Indexer API guide](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html)
- [Secure the Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/securing-indexer-api.html)

### Implementation order

1. Create a server-side SentinelGrid API; never connect browser JavaScript directly to ports 9200 or 55000.
2. Create read-only Wazuh credentials for the API. Do not use the Wazuh `admin` account.
3. Store credentials in environment variables outside Git.
4. Query Wazuh Server API for agent health and inventory.
5. Query Wazuh Indexer API for `wazuh-alerts-*` and, later, approved archive queries.
6. Normalize Wazuh fields into SentinelGrid's alert, asset, source, and incident shapes.
7. Implement read-only routes first: `/api/health`, `/api/agents`, `/api/alerts`, and `/api/assets`.
8. Add authentication, authorization, input validation, request limits, TLS verification, and audit logs.
9. Replace SentinelGrid's generated live events with API data. Keep demo mode as a clearly labeled switch.

### Completion gate

Every SentinelGrid alert must display its Wazuh index, document ID, agent, source timestamp, and rule ID. Refreshing the page must not manufacture new alerts.

## Stage 7: Add SQL Server reporting storage

This stage now runs before Stage 6. A Python loader reads `wazuh-alerts-*` from the Wazuh Indexer and writes to SQL Server, so the warehouse and Power BI do not wait on the SentinelGrid API.

As built:

1. Install SQL Server 2025 Developer (Basic install, default instance) and, optionally, SSMS.
2. Create the Python environment and the warehouse. The SQL scripts are idempotent and also cap SQL Server at 4 GB of RAM:

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install pyodbc requests
.venv\Scripts\python.exe warehouse\apply_sql.py
```

3. In the Wazuh dashboard (`Indexer management > Security`), create role `sentinelgrid_reader` (cluster: `cluster_composite_ops_ro`; indices `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`: `read`), create internal user `sentinelgrid_loader`, and map the user to the role. Never use `admin`.
4. The Indexer listens only on `127.0.0.1` inside the VM, so do **not** open 9200. Create a dedicated SSH key on Windows and install it on the VM restricted to one port forward:

```powershell
ssh-keygen -t ed25519 -f $HOME\.ssh\sentinelgrid_loader -N '""' -C sentinelgrid-loader
```

```bash
# on the VM, one line in ~/.ssh/authorized_keys:
restrict,port-forwarding,permitopen="127.0.0.1:9200",command="/bin/false" ssh-ed25519 AAAA... sentinelgrid-loader
```

5. Extract only `root-ca.pem` from the private `wazuh-install-files.tar` backup, copy `loader/.env.example` to `loader/.env` (git-ignored), and fill in the password.
6. Run `.venv\Scripts\python.exe loader\wazuh_to_sql.py` twice. The second run must insert only new alerts.
7. Schedule it every 15 minutes as `\SentinelGrid\SentinelGridLoader`, running `.venv\Scripts\pythonw.exe` so no console window appears. If Wazuh is unreachable, the run is logged as failed in `sg.load_runs` and the next run catches up.

### Programs and documentation

- [SQL Server 2025 Developer download](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
- [Install SQL Server Management Studio 22](https://learn.microsoft.com/en-us/ssms/install/install)
- [Secure SQL Server](https://learn.microsoft.com/en-us/sql/relational-databases/security/secure-sql-server?view=sql-server-ver17)

### Steps

1. Install SQL Server 2025 Developer Edition for this non-production lab and install SSMS 22.
2. Create a database named `SentinelGridWarehouse`.
3. Create tables for assets, alerts, incidents, incident events, MITRE techniques, analyst actions, and daily metrics.
4. Keep raw high-volume telemetry in Wazuh Indexer. Copy only curated alerts, case history, and summarized metrics to SQL.
5. Give the SentinelGrid API a narrowly scoped writer account.
6. Give Power BI a separate read-only account with access to reporting views, not operational tables.
7. Build a scheduled incremental load keyed by Wazuh document ID and timestamp so reruns do not duplicate rows.

### Completion gate

Closing or assigning an incident in SentinelGrid must persist in SQL, and a reporting view must return incident counts without exposing Wazuh or API credentials.

## Stage 8: Build the Power BI report

### Programs and documentation

- [Install Power BI Desktop](https://learn.microsoft.com/en-us/power-bi/fundamentals/desktop-get-the-desktop)
- [Connect Power BI to SQL Server](https://learn.microsoft.com/en-us/power-query/connectors/sql-server)

### Steps

1. Install the 64-bit Power BI Desktop from Microsoft Store or Microsoft's download page.
2. Select `Get Data > SQL Server database`.
3. Enter the SQL Server and `SentinelGridWarehouse` database names.
4. Start with Import mode; it is simpler and appropriate for a personal reporting lab.
5. Connect with the dedicated read-only reporting account.
6. Load reporting views for incidents, assets, rules, MITRE coverage, and daily metrics.
7. Build pages for executive overview, incident trends, response time, affected assets, rule performance, and ATT&CK coverage.
8. Keep the report local until all names, hostnames, addresses, and case notes are reviewed for sensitive information.

### Completion gate

A Power BI visual must trace back to a SQL reporting view, which must trace back to a SentinelGrid incident or Wazuh alert ID.

## Recommended first milestone

Stop after Stage 4. Do not install SQL Server, Power BI, or Suricata until one real Windows event is visible end to end. That first verified event is the foundation of the entire platform.

Reached on 2026-09-30.

## Operating the lab

- **Startup:** Sysmon and the Wazuh agent start with Windows. Hyper-V saves the VM when Windows shuts down and resumes it at boot if it was running. The dashboard can take up to 3 minutes after a cold VM boot.
- **If the dashboard will not load after a Windows restart:** the Default Switch may have moved to a new subnet (observed: 172.26.176.0/20 to 192.168.160.0/20) while the resumed VM kept its old IP. Restart the VM from an elevated PowerShell with `Restart-VM -Name SentinelGrid-Wazuh -Force` and wait 3 minutes.
- **Turning the lab off:** `Stop-VM -Name SentinelGrid-Wazuh` shuts it down cleanly, and it stays off across Windows restarts until `Start-VM -Name SentinelGrid-Wazuh`.
- **SQL Server starts about 2-3 minutes after boot** (Automatic, Delayed Start). Loader runs in that window fail and are logged in `sg.load_runs`; the next run catches up on everything queued.
- **Resource cost:** the VM reserves 8 GB of RAM while running. Sysmon and the agent are negligible.
- **Do not** run `do-release-upgrade` on the VM. Stay on Ubuntu 24.04 until Wazuh supports a newer release.
