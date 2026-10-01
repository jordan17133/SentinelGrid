-- SentinelGrid warehouse: case log. An alert is a signal; a case is the
-- investigation of one or more alerts, with an owner, a status, a verdict and
-- a history. Cases are opened, assigned and closed with warehouse/cases.py.
-- The seed below records the investigations in triage/ and only inserts
-- missing rows, so later changes made with cases.py survive a re-run.

USE SentinelGridWarehouse;
GO

IF OBJECT_ID(N'sg.cases') IS NULL
CREATE TABLE sg.cases (
    case_id          int IDENTITY(1, 1) NOT NULL CONSTRAINT PK_cases PRIMARY KEY,
    case_key         nvarchar(64)   NOT NULL CONSTRAINT UQ_cases_key UNIQUE,
    title            nvarchar(200)  NOT NULL,
    severity         nvarchar(16)   NOT NULL CONSTRAINT CK_cases_severity CHECK (severity IN (N'Critical', N'High', N'Medium', N'Low')),
    status           nvarchar(16)   NOT NULL CONSTRAINT CK_cases_status CHECK (status IN (N'Open', N'In progress', N'Closed')),
    assigned_to      nvarchar(64)   NULL,
    verdict          nvarchar(32)   NULL CONSTRAINT CK_cases_verdict CHECK (verdict IN (N'True positive', N'Benign', N'Low risk')),
    first_alert_utc  datetime2(0)   NOT NULL,   -- earliest alert in the case: when detection happened
    opened_utc       datetime2(0)   NULL,       -- when the case was opened (not recorded for the first investigations)
    closed_utc       datetime2(0)   NULL,
    report_path      nvarchar(256)  NULL,
    summary          nvarchar(400)  NULL,
    CONSTRAINT CK_cases_closed CHECK (status <> N'Closed' OR (verdict IS NOT NULL AND closed_utc IS NOT NULL))
);
GO

IF OBJECT_ID(N'sg.case_rules') IS NULL
CREATE TABLE sg.case_rules (
    case_id  int NOT NULL CONSTRAINT FK_case_rules_case REFERENCES sg.cases (case_id),
    rule_id  int NOT NULL,
    CONSTRAINT PK_case_rules PRIMARY KEY (case_id, rule_id)
);
GO

-- Every change to a case, in order: the case history.
IF OBJECT_ID(N'sg.case_events') IS NULL
CREATE TABLE sg.case_events (
    event_id   int IDENTITY(1, 1) NOT NULL CONSTRAINT PK_case_events PRIMARY KEY,
    case_id    int            NOT NULL CONSTRAINT FK_case_events_case REFERENCES sg.cases (case_id),
    event_utc  datetime2(0)   NOT NULL CONSTRAINT DF_case_events_utc DEFAULT SYSUTCDATETIME(),
    action     nvarchar(16)   NOT NULL CONSTRAINT CK_case_events_action CHECK (action IN (N'Opened', N'Assigned', N'Note', N'Closed', N'Reopened')),
    actor      nvarchar(64)   NOT NULL,
    detail     nvarchar(400)  NULL
);
GO

-- Seed: the investigations written up in triage/. Closed time is when the
-- report was committed; the first cases were not opened as records, so their
-- time to verdict is measured from the first alert.
MERGE sg.cases AS t
USING (VALUES
    (N'2026-09-30-installer-92213', N'Installers dropping executables in Temp', N'Critical', N'Closed', N'Jordan', N'Benign',
     '2026-09-30 08:47:09', NULL, '2026-09-30 08:57:16', N'triage/2026-09-30-rule-92213-installer-false-positive.md',
     N'Wazuh agent and Sysmon installers writing to Temp during setup.'),
    (N'2026-09-30-watchdog-92213', N'36 Critical alerts an hour from scheduled PowerShell', N'Critical', N'Closed', N'Jordan', N'Benign',
     '2026-09-30 08:47:09', NULL, '2026-09-30 20:11:33', N'triage/2026-09-30-rule-92213-powershell-policy-test-noise.md',
     N'Three scheduled watchdog tasks; tuned with rule 100100.'),
    (N'2026-09-30-sdbinst-92058', N'Hourly sdbinst.exe launches', N'High', N'Closed', N'Jordan', N'Benign',
     '2026-09-30 08:53:04', NULL, '2026-09-30 23:20:29', N'triage/2026-09-30-rule-92058-sdbinst-pca-maintenance.md',
     N'Microsoft-signed Program Compatibility Assistant maintenance; tuned with rule 100101.'),
    (N'2026-10-01-ssh-test', N'Failed SSH logins against the Wazuh server', N'Medium', N'Closed', N'Jordan', N'True positive',
     '2026-10-01 21:31:40', NULL, '2026-10-01 21:44:42', N'triage/2026-10-01-ssh-failed-logins-wazuh-server.md',
     N'Controlled password-guessing test (T1110.001), detected end to end.'),
    (N'2026-10-01-after-tuning', N'Critical alerts left after tuning, and rule 92217', N'Critical', N'Closed', N'Jordan', N'Benign',
     '2026-09-30 11:28:29', NULL, '2026-10-01 22:01:41', N'triage/2026-10-01-rules-92213-92217-after-tuning.md',
     N'AMD crash reporter after GPU driver crashes, build tooling Add-Type, software installs.'),
    (N'2026-10-01-baseline-review', N'Baseline review of every remaining fired rule', N'High', N'Closed', N'Jordan', N'Benign',
     '2026-09-30 08:32:03', NULL, '2026-10-01 22:08:07', N'triage/2026-10-01-baseline-review-remaining-rules.md',
     N'28 rules: 27 benign with a named source, 1 split out as its own open case.'),
    (N'2026-10-01-loopback-share', N'Loopback admin share access, source process unknown', N'Low', N'Open', N'Jordan', NULL,
     '2026-10-01 16:42:25', '2026-10-01 22:08:07', NULL, N'triage/2026-10-01-baseline-review-remaining-rules.md',
     N'C$ and IPC$ opened over ::1 by the user''s account; enable event 5145 to identify the process.')
) AS s (case_key, title, severity, status, assigned_to, verdict, first_alert_utc, opened_utc, closed_utc, report_path, summary)
ON t.case_key = s.case_key
WHEN NOT MATCHED THEN INSERT (case_key, title, severity, status, assigned_to, verdict, first_alert_utc, opened_utc, closed_utc, report_path, summary)
    VALUES (s.case_key, s.title, s.severity, s.status, s.assigned_to, s.verdict, s.first_alert_utc, s.opened_utc, s.closed_utc, s.report_path, s.summary);
GO

INSERT INTO sg.case_rules (case_id, rule_id)
SELECT c.case_id, s.rule_id
FROM (VALUES
    (N'2026-09-30-installer-92213', 92213), (N'2026-09-30-watchdog-92213', 92213), (N'2026-09-30-watchdog-92213', 100100),
    (N'2026-09-30-sdbinst-92058', 92058), (N'2026-09-30-sdbinst-92058', 100101),
    (N'2026-10-01-ssh-test', 5710), (N'2026-10-01-ssh-test', 5503), (N'2026-10-01-ssh-test', 5760), (N'2026-10-01-ssh-test', 2502),
    (N'2026-10-01-after-tuning', 92213), (N'2026-10-01-after-tuning', 92217), (N'2026-10-01-after-tuning', 92006),
    (N'2026-10-01-baseline-review', 750), (N'2026-10-01-baseline-review', 751), (N'2026-10-01-baseline-review', 92052),
    (N'2026-10-01-baseline-review', 92032), (N'2026-10-01-baseline-review', 91809), (N'2026-10-01-baseline-review', 91823),
    (N'2026-10-01-baseline-review', 100110), (N'2026-10-01-baseline-review', 5501), (N'2026-10-01-baseline-review', 5715),
    (N'2026-10-01-loopback-share', 67017)
) AS s (case_key, rule_id)
JOIN sg.cases AS c ON c.case_key = s.case_key
WHERE NOT EXISTS (SELECT 1 FROM sg.case_rules AS r WHERE r.case_id = c.case_id AND r.rule_id = s.rule_id);
GO

INSERT INTO sg.case_events (case_id, event_utc, action, actor, detail)
SELECT c.case_id, COALESCE(c.closed_utc, c.opened_utc),
       CASE WHEN c.status = N'Closed' THEN N'Closed' ELSE N'Opened' END, N'Jordan',
       CASE WHEN c.status = N'Closed' THEN c.verdict + N': ' + c.report_path ELSE N'Split out of the baseline review' END
FROM sg.cases AS c
WHERE c.case_key IN (N'2026-09-30-installer-92213', N'2026-09-30-watchdog-92213', N'2026-09-30-sdbinst-92058', N'2026-10-01-ssh-test',
                     N'2026-10-01-after-tuning', N'2026-10-01-baseline-review', N'2026-10-01-loopback-share')
  AND NOT EXISTS (SELECT 1 FROM sg.case_events AS e WHERE e.case_id = c.case_id);
GO

-- One row per case with its timing. Time to verdict runs from the first alert
-- to closing; open cases show their age instead.
CREATE OR ALTER VIEW rpt.cases AS
SELECT
    c.case_id,
    CONCAT(N'SG-', FORMAT(c.case_id, N'000')) AS case_number,
    c.title,
    c.severity,
    CASE c.severity WHEN N'Critical' THEN 1 WHEN N'High' THEN 2 WHEN N'Medium' THEN 3 ELSE 4 END AS severity_order,
    c.status,
    c.assigned_to,
    ISNULL(c.verdict, N'Pending') AS verdict,
    CAST(c.first_alert_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS first_alert_local,
    CAST(c.closed_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS closed_local,
    CAST(DATEDIFF(minute, c.first_alert_utc, c.closed_utc) / 60.0 AS decimal(9, 1)) AS hours_to_verdict,
    CASE WHEN c.closed_utc IS NULL
         THEN CAST(DATEDIFF(minute, c.first_alert_utc, SYSUTCDATETIME()) / 60.0 AS decimal(9, 1)) END AS open_age_hours,
    (SELECT STRING_AGG(CAST(r.rule_id AS nvarchar(12)), N', ') WITHIN GROUP (ORDER BY r.rule_id)
     FROM sg.case_rules AS r WHERE r.case_id = c.case_id) AS rules,
    (SELECT COUNT(*) FROM sg.alerts AS a
     WHERE a.rule_id IN (SELECT r.rule_id FROM sg.case_rules AS r WHERE r.case_id = c.case_id)
       AND a.alert_ts_utc >= c.first_alert_utc
       AND a.alert_ts_utc <= ISNULL(c.closed_utc, SYSUTCDATETIME())) AS alerts_in_case,
    c.report_path,
    c.summary
FROM sg.cases AS c;
GO
