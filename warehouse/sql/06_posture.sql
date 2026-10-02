-- Watchtide warehouse: endpoint posture (vulnerabilities and CIS benchmark).
--
-- Wazuh reports posture changes as ordinary alerts, so they are already in
-- sg.alerts. This script extracts them into typed tables, so the posture pages
-- trace back to Wazuh document IDs and survive the Low-severity raw_json trim:
--   vulnerability-detector alerts  -> sg.vulnerability_events  (e.g. rule 23502 "CVE ... was solved")
--   SCA check alerts               -> sg.sca_check_events      (rules 19007-19011, one per check result or change)
--   SCA summary alerts             -> sg.sca_scan_summaries    (rules 19003-19005, one per scan with a score)
-- sg.refresh_posture_events runs after every loader run and is also the backfill.
-- Safe to re-run.

USE SentinelGridWarehouse;
GO

-- Posture events are found by rule, so give the alerts table a rule index.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_alerts_rule' AND object_id = OBJECT_ID(N'sg.alerts'))
    CREATE INDEX IX_alerts_rule ON sg.alerts (rule_id) INCLUDE (alert_ts_utc, agent_id);
GO

IF OBJECT_ID(N'sg.vulnerability_events') IS NULL
CREATE TABLE sg.vulnerability_events (
    doc_id           varchar(64)    NOT NULL CONSTRAINT PK_vulnerability_events PRIMARY KEY,
    agent_id         varchar(16)    NOT NULL,
    event_ts_utc     datetime2(3)   NOT NULL,
    status           varchar(16)    NOT NULL,   -- Active (detected) or Solved
    cve_id           varchar(32)    NOT NULL,
    package_name     nvarchar(256)  NOT NULL,
    package_version  nvarchar(128)  NOT NULL,
    severity         varchar(16)    NOT NULL,   -- Unscored when Wazuh sent no severity
    base_score       decimal(3, 1)  NULL,
    CONSTRAINT FK_vulnerability_events_alert FOREIGN KEY (doc_id) REFERENCES sg.alerts (doc_id) ON DELETE CASCADE
);
GO

IF OBJECT_ID(N'sg.sca_check_events') IS NULL
CREATE TABLE sg.sca_check_events (
    doc_id           varchar(64)    NOT NULL CONSTRAINT PK_sca_check_events PRIMARY KEY,
    agent_id         varchar(16)    NOT NULL,
    event_ts_utc     datetime2(3)   NOT NULL,
    scan_id          varchar(32)    NULL,
    policy_name      nvarchar(256)  NOT NULL,
    check_id         int            NOT NULL,
    title            nvarchar(512)  NOT NULL,
    cis_ref          varchar(32)    NULL,        -- benchmark recommendation number, e.g. 2.3.10.3
    cis_section      int            NULL,        -- its first component, e.g. 2
    result           varchar(32)    NOT NULL,    -- passed, failed, not applicable
    previous_result  varchar(32)    NULL,        -- NULL on a check's first scan
    CONSTRAINT FK_sca_check_events_alert FOREIGN KEY (doc_id) REFERENCES sg.alerts (doc_id) ON DELETE CASCADE
);
GO

IF OBJECT_ID(N'sg.sca_scan_summaries') IS NULL
CREATE TABLE sg.sca_scan_summaries (
    doc_id           varchar(64)    NOT NULL CONSTRAINT PK_sca_scan_summaries PRIMARY KEY,
    agent_id         varchar(16)    NOT NULL,
    scan_ts_utc      datetime2(3)   NOT NULL,
    scan_id          varchar(32)    NULL,
    policy_name      nvarchar(256)  NOT NULL,
    passed           int            NOT NULL,
    failed           int            NOT NULL,
    not_applicable   int            NOT NULL,
    total_checks     int            NOT NULL,
    CONSTRAINT FK_sca_scan_summaries_alert FOREIGN KEY (doc_id) REFERENCES sg.alerts (doc_id) ON DELETE CASCADE
);
GO

-- Benchmark section names, for readable section charts.
IF OBJECT_ID(N'sg.cis_sections') IS NULL
CREATE TABLE sg.cis_sections (
    policy_name   nvarchar(256)  NOT NULL,
    cis_section   int            NOT NULL,
    section_name  nvarchar(128)  NOT NULL,
    CONSTRAINT PK_cis_sections PRIMARY KEY (policy_name, cis_section)
);
GO
MERGE sg.cis_sections AS t
USING (VALUES
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 1,  N'Account Policies'),
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 2,  N'Local Policies'),
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 5,  N'System Services'),
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 9,  N'Windows Firewall'),
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 17, N'Advanced Audit Policy'),
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 18, N'Administrative Templates'),
    (N'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0', 19, N'Administrative Templates (User)'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 1, N'Initial Setup'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 2, N'Services'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 3, N'Network'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 4, N'Host Based Firewall'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 5, N'Access Control'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 6, N'Logging and Auditing'),
    (N'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.', 7, N'System Maintenance')
) AS s (policy_name, cis_section, section_name)
ON t.policy_name = s.policy_name AND t.cis_section = s.cis_section
WHEN MATCHED THEN UPDATE SET section_name = s.section_name
WHEN NOT MATCHED THEN INSERT (policy_name, cis_section, section_name) VALUES (s.policy_name, s.cis_section, s.section_name);
GO

-- Extract posture events from alerts not yet extracted. Cheap when there is
-- nothing new, because it only looks at alerts from posture rules.
CREATE OR ALTER PROCEDURE sg.refresh_posture_events
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO sg.vulnerability_events (doc_id, agent_id, event_ts_utc, status, cve_id, package_name,
                                         package_version, severity, base_score)
    SELECT a.doc_id, a.agent_id, a.alert_ts_utc,
           ISNULL(JSON_VALUE(a.raw_json, '$.data.vulnerability.status'), 'Unknown'),
           JSON_VALUE(a.raw_json, '$.data.vulnerability.cve'),
           JSON_VALUE(a.raw_json, '$.data.vulnerability.package.name'),
           ISNULL(JSON_VALUE(a.raw_json, '$.data.vulnerability.package.version'), ''),
           CASE WHEN JSON_VALUE(a.raw_json, '$.data.vulnerability.severity') IN ('Critical', 'High', 'Medium', 'Low')
                THEN JSON_VALUE(a.raw_json, '$.data.vulnerability.severity') ELSE 'Unscored' END,
           CASE WHEN TRY_CAST(JSON_VALUE(a.raw_json, '$.data.vulnerability.score.base') AS decimal(4, 1)) BETWEEN 0 AND 10
                THEN TRY_CAST(JSON_VALUE(a.raw_json, '$.data.vulnerability.score.base') AS decimal(4, 1)) END
    FROM sg.alerts AS a
    WHERE a.rule_id IN (SELECT rule_id FROM sg.rules WHERE N',' + rule_groups + N',' LIKE N'%,vulnerability-detector,%')
      AND a.raw_json IS NOT NULL
      AND JSON_VALUE(a.raw_json, '$.data.vulnerability.cve') IS NOT NULL
      AND JSON_VALUE(a.raw_json, '$.data.vulnerability.package.name') IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM sg.vulnerability_events AS v WHERE v.doc_id = a.doc_id);

    DECLARE @sca TABLE (doc_id varchar(64) PRIMARY KEY, agent_id varchar(16), ts datetime2(3), j nvarchar(max));
    INSERT INTO @sca
    SELECT a.doc_id, a.agent_id, a.alert_ts_utc, JSON_QUERY(a.raw_json, '$.data.sca')
    FROM sg.alerts AS a
    WHERE a.rule_id IN (SELECT rule_id FROM sg.rules WHERE N',' + rule_groups + N',' LIKE N'%,sca,%')
      AND a.raw_json IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM sg.sca_check_events AS c WHERE c.doc_id = a.doc_id)
      AND NOT EXISTS (SELECT 1 FROM sg.sca_scan_summaries AS s WHERE s.doc_id = a.doc_id);

    INSERT INTO sg.sca_check_events (doc_id, agent_id, event_ts_utc, scan_id, policy_name, check_id, title,
                                     cis_ref, cis_section, result, previous_result)
    SELECT x.doc_id, x.agent_id, x.ts,
           JSON_VALUE(x.j, '$.scan_id'),
           JSON_VALUE(x.j, '$.policy'),
           TRY_CAST(JSON_VALUE(x.j, '$.check.id') AS int),
           LEFT(JSON_VALUE(x.j, '$.check.title'), 512),
           c.cis_ref,
           TRY_CAST(LEFT(c.cis_ref, CHARINDEX('.', c.cis_ref + '.') - 1) AS int),
           JSON_VALUE(x.j, '$.check.result'),
           JSON_VALUE(x.j, '$.check.previous_result')
    FROM @sca AS x
    CROSS APPLY (SELECT LEFT(JSON_VALUE(x.j, '$.check.compliance.cis'), 32) AS cis_ref) AS c
    WHERE JSON_VALUE(x.j, '$.type') = 'check'
      AND TRY_CAST(JSON_VALUE(x.j, '$.check.id') AS int) IS NOT NULL
      AND JSON_VALUE(x.j, '$.check.result') IS NOT NULL;

    INSERT INTO sg.sca_scan_summaries (doc_id, agent_id, scan_ts_utc, scan_id, policy_name, passed, failed,
                                       not_applicable, total_checks)
    SELECT x.doc_id, x.agent_id, x.ts,
           JSON_VALUE(x.j, '$.scan_id'),
           JSON_VALUE(x.j, '$.policy'),
           TRY_CAST(JSON_VALUE(x.j, '$.passed') AS int),
           TRY_CAST(JSON_VALUE(x.j, '$.failed') AS int),
           ISNULL(TRY_CAST(JSON_VALUE(x.j, '$.invalid') AS int), 0),
           TRY_CAST(JSON_VALUE(x.j, '$.total_checks') AS int)
    FROM @sca AS x
    WHERE JSON_VALUE(x.j, '$.type') = 'summary'
      AND TRY_CAST(JSON_VALUE(x.j, '$.passed') AS int) IS NOT NULL
      AND TRY_CAST(JSON_VALUE(x.j, '$.failed') AS int) IS NOT NULL;
END;
GO

EXEC sg.refresh_posture_events;
GO

-- Every vulnerability finding since monitoring began: open now (latest daily
-- snapshot) or resolved (Wazuh's "was solved" alert, kept as evidence).
CREATE OR ALTER VIEW rpt.vulnerability_findings AS
WITH open_findings AS (
    SELECT v.agent_id, v.cve_id, v.package_name, v.package_version,
           CASE WHEN v.severity IN ('Critical', 'High', 'Medium', 'Low') THEN v.severity ELSE 'Unscored' END AS severity,
           v.base_score
    FROM sg.vulnerability_snapshots AS v
    WHERE v.snapshot_date = (SELECT MAX(snapshot_date) FROM sg.vulnerability_snapshots)
),
solved AS (
    SELECT e.*, ROW_NUMBER() OVER (PARTITION BY e.agent_id, e.cve_id, e.package_name, e.package_version
                                   ORDER BY e.event_ts_utc DESC) AS rn
    FROM sg.vulnerability_events AS e
    WHERE e.status = 'Solved'
),
findings AS (
    SELECT agent_id, cve_id, package_name, package_version, severity, base_score,
           'Open' AS status, CAST(NULL AS datetime2(3)) AS resolved_at_utc, CAST(NULL AS varchar(64)) AS evidence_doc_id
    FROM open_findings
    UNION ALL
    SELECT s.agent_id, s.cve_id, s.package_name, s.package_version, s.severity, s.base_score,
           'Resolved', s.event_ts_utc, s.doc_id
    FROM solved AS s
    WHERE s.rn = 1
      AND NOT EXISTS (SELECT 1 FROM open_findings AS o
                      WHERE o.agent_id = s.agent_id AND o.cve_id = s.cve_id
                        AND o.package_name = s.package_name AND o.package_version = s.package_version)
)
SELECT
    ag.agent_name,
    f.cve_id,
    f.package_name,
    f.package_version,
    f.severity,
    CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END AS severity_sort,
    f.base_score,
    f.status,
    CAST(f.resolved_at_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS resolved_at_local,
    f.evidence_doc_id
FROM findings AS f
JOIN sg.agents AS ag ON ag.agent_id = f.agent_id;
GO

-- One row per benchmark check: the first result Wazuh reported and the latest.
-- If the earliest stored event is already a change, its previous_result is the baseline.
CREATE OR ALTER VIEW rpt.cis_check_results AS
WITH ranked AS (
    SELECT e.*,
           ROW_NUMBER() OVER (PARTITION BY e.agent_id, e.policy_name, e.check_id ORDER BY e.event_ts_utc, e.doc_id) AS first_rn,
           ROW_NUMBER() OVER (PARTITION BY e.agent_id, e.policy_name, e.check_id ORDER BY e.event_ts_utc DESC, e.doc_id DESC) AS last_rn
    FROM sg.sca_check_events AS e
)
SELECT
    ag.agent_name,
    f.policy_name,
    f.check_id,
    f.title,
    f.cis_ref,
    f.cis_section,
    CONCAT(f.cis_section, '. ', ISNULL(cs.section_name, N'Other')) AS section_label,
    COALESCE(f.previous_result, f.result) AS baseline_result,
    l.result AS current_result,
    CASE WHEN COALESCE(f.previous_result, f.result) = l.result THEN 'Unchanged'
         WHEN l.result = 'passed' THEN 'Fixed'
         WHEN COALESCE(f.previous_result, f.result) = 'passed' THEN 'Regressed'
         ELSE 'Changed' END AS change_status,
    CAST(l.event_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS last_change_local,
    l.doc_id AS evidence_doc_id
FROM ranked AS f
JOIN ranked AS l
  ON l.agent_id = f.agent_id AND l.policy_name = f.policy_name AND l.check_id = f.check_id AND l.last_rn = 1
JOIN sg.agents AS ag ON ag.agent_id = f.agent_id
LEFT JOIN sg.cis_sections AS cs ON cs.policy_name = f.policy_name AND cs.cis_section = f.cis_section
WHERE f.first_rn = 1;
GO

-- Score after every scan. Wazuh's score is passed / (passed + failed); its alert
-- truncates to a whole number, so it is recomputed here to one decimal.
-- A first scan with no summary alert is rebuilt from its per-check alerts.
CREATE OR ALTER VIEW rpt.cis_score_history AS
WITH summaries AS (   -- Wazuh occasionally sends the same scan's summary twice
    SELECT *, ROW_NUMBER() OVER (PARTITION BY agent_id, policy_name, scan_id ORDER BY scan_ts_utc, doc_id) AS rn
    FROM sg.sca_scan_summaries
),
scans AS (
    SELECT agent_id, policy_name, scan_ts_utc, passed, failed, not_applicable, total_checks,
           'Wazuh SCA summary alert' AS source, doc_id AS evidence_doc_id
    FROM summaries
    WHERE rn = 1
    UNION ALL
    SELECT e.agent_id, e.policy_name, MIN(e.event_ts_utc),
           SUM(CASE WHEN e.result = 'passed' THEN 1 ELSE 0 END),
           SUM(CASE WHEN e.result = 'failed' THEN 1 ELSE 0 END),
           SUM(CASE WHEN e.result NOT IN ('passed', 'failed') THEN 1 ELSE 0 END),
           COUNT(*),
           'Rebuilt from first-scan check alerts', NULL
    FROM sg.sca_check_events AS e
    WHERE e.previous_result IS NULL
      AND e.scan_id = (SELECT TOP 1 f.scan_id FROM sg.sca_check_events AS f
                       WHERE f.agent_id = e.agent_id AND f.policy_name = e.policy_name
                       ORDER BY f.event_ts_utc, f.doc_id)
      AND NOT EXISTS (SELECT 1 FROM sg.sca_scan_summaries AS s
                      WHERE s.agent_id = e.agent_id AND s.scan_id = e.scan_id)
    GROUP BY e.agent_id, e.policy_name, e.scan_id
)
SELECT
    ag.agent_name,
    s.policy_name,
    CAST(s.scan_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS scan_time_local,
    s.passed,
    s.failed,
    s.not_applicable,
    s.total_checks,
    CAST(ROUND(100.0 * s.passed / NULLIF(s.passed + s.failed, 0), 1) AS decimal(4, 1)) AS score_pct,
    ROW_NUMBER() OVER (PARTITION BY s.agent_id, s.policy_name ORDER BY s.scan_ts_utc) AS scan_number,
    s.source,
    s.evidence_doc_id
FROM scans AS s
JOIN sg.agents AS ag ON ag.agent_id = s.agent_id;
GO
