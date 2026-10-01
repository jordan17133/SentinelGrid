-- SentinelGrid warehouse: reporting views for Power BI.
-- Power BI reads only the rpt schema, never the sg tables directly.
-- Times are stored in UTC and converted to US Eastern for display.
-- Severity bands follow the Wazuh dashboard: 0-6 Low, 7-11 Medium, 12-14 High, 15 Critical.

USE SentinelGridWarehouse;
GO

CREATE OR ALTER VIEW rpt.alerts AS
SELECT
    a.doc_id,
    a.index_name,
    a.wazuh_alert_id,
    a.alert_ts_utc,
    CAST(a.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS alert_time_local,
    CAST(a.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS date)         AS alert_date_local,
    DATEPART(hour, a.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time')       AS alert_hour_local,
    DATEADD(hour, DATEDIFF(hour, 0, CAST(a.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0))), 0)
                                                                                                 AS alert_hour_start_local,
    ag.agent_name,
    a.rule_id,
    a.rule_description,
    a.rule_level,
    CASE WHEN a.rule_level >= 15 THEN 'Critical'
         WHEN a.rule_level >= 12 THEN 'High'
         WHEN a.rule_level >= 7  THEN 'Medium'
         ELSE 'Low' END AS severity_band,
    CASE WHEN a.rule_level >= 15 THEN 1
         WHEN a.rule_level >= 12 THEN 2
         WHEN a.rule_level >= 7  THEN 3
         ELSE 4 END AS severity_sort,
    a.event_channel,
    a.win_event_id,
    a.process_image,
    a.parent_image,
    a.command_line,
    a.target_filename,
    a.user_name
FROM sg.alerts AS a
JOIN sg.agents AS ag ON ag.agent_id = a.agent_id;
GO

CREATE OR ALTER VIEW rpt.alert_techniques AS
SELECT
    at.doc_id,
    at.technique_id,
    t.technique_name,
    CONCAT(at.technique_id, ' ', t.technique_name) AS technique_label
FROM sg.alert_techniques AS at
JOIN sg.mitre_techniques AS t ON t.technique_id = at.technique_id;
GO

CREATE OR ALTER VIEW rpt.alert_tactics AS
SELECT doc_id, tactic
FROM sg.alert_tactics;
GO

CREATE OR ALTER VIEW rpt.rule_performance AS
SELECT
    r.rule_id,
    r.description,
    r.rule_level,
    r.rule_groups,
    COUNT(a.doc_id)                                                                   AS total_alerts,
    SUM(CASE WHEN a.alert_ts_utc >= DATEADD(day, -7, SYSUTCDATETIME()) THEN 1 ELSE 0 END) AS alerts_last_7_days,
    COUNT(DISTINCT CAST(a.alert_ts_utc AS date))                                      AS active_days,
    MIN(a.alert_ts_utc)                                                               AS first_alert_utc,
    MAX(a.alert_ts_utc)                                                               AS last_alert_utc
FROM sg.rules AS r
LEFT JOIN sg.alerts AS a ON a.rule_id = r.rule_id
GROUP BY r.rule_id, r.description, r.rule_level, r.rule_groups;
GO

CREATE OR ALTER VIEW rpt.agent_health AS
SELECT
    ag.agent_id,
    ag.agent_name,
    ag.agent_ip,
    ag.first_seen_utc,
    ag.last_seen_utc,
    DATEDIFF(minute, ag.last_seen_utc, SYSUTCDATETIME()) AS minutes_since_last_alert,
    (SELECT COUNT(*) FROM sg.alerts AS a
      WHERE a.agent_id = ag.agent_id
        AND a.alert_ts_utc >= DATEADD(hour, -24, SYSUTCDATETIME())) AS alerts_last_24h
FROM sg.agents AS ag;
GO

CREATE OR ALTER VIEW rpt.vulnerability_trend AS
SELECT
    v.snapshot_date,
    ag.agent_name,
    v.severity,
    COUNT(*) AS findings
FROM sg.vulnerability_snapshots AS v
JOIN sg.agents AS ag ON ag.agent_id = v.agent_id
GROUP BY v.snapshot_date, ag.agent_name, v.severity;
GO

CREATE OR ALTER VIEW rpt.vulnerabilities_current AS
SELECT
    v.snapshot_date,
    ag.agent_name,
    v.cve_id,
    v.package_name,
    v.package_version,
    v.severity,
    v.base_score,
    v.detected_at_utc
FROM sg.vulnerability_snapshots AS v
JOIN sg.agents AS ag ON ag.agent_id = v.agent_id
WHERE v.snapshot_date = (SELECT MAX(snapshot_date) FROM sg.vulnerability_snapshots);
GO

CREATE OR ALTER VIEW rpt.load_runs AS
SELECT
    run_id,
    started_at_utc,
    finished_at_utc,
    DATEDIFF(second, started_at_utc, finished_at_utc) AS duration_seconds,
    status,
    watermark_from,
    watermark_to,
    alerts_fetched,
    alerts_inserted,
    vulns_snapshotted,
    error_message,
    CAST(started_at_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS started_at_local,
    DATEADD(hour, DATEDIFF(hour, 0, CAST(started_at_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0))), 0)
                                                                                                 AS started_hour_local,
    CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END AS succeeded
FROM sg.load_runs;
GO
