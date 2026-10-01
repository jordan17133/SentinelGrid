-- SentinelGrid warehouse: data lifecycle (tiered retention).
--
--   Medium, High, Critical alerts (level 7+)   full detail forever
--   Low alerts (level 0-6)                     full detail 365 days, then raw_json
--                                              trimmed; rows kept forever by default
--                                              (pass @low_keep_days to delete instead)
--   Daily summaries (per rule and technique)   forever (a few KB per day)
--
-- Summaries are rebuilt for recent days on every loader run, long before any
-- detail is deleted, so trend history survives detail retention.
-- Safe to re-run.

USE SentinelGridWarehouse;
GO

-- Hard ceiling on the data file so the warehouse can never fill the host drive.
DECLARE @file sysname = (SELECT name FROM sys.database_files WHERE type_desc = 'ROWS');
EXEC (N'ALTER DATABASE SentinelGridWarehouse MODIFY FILE (NAME = ' + @file + N', MAXSIZE = 100GB)');
GO

-- Trimmed alerts keep their columns but drop the raw document.
ALTER TABLE sg.alerts ALTER COLUMN raw_json nvarchar(max) NULL;
GO

IF OBJECT_ID(N'sg.daily_alert_summary') IS NULL
CREATE TABLE sg.daily_alert_summary (
    summary_date    date          NOT NULL,   -- US Eastern calendar date
    agent_id        varchar(16)   NOT NULL,
    rule_id         int           NOT NULL,
    rule_level      tinyint       NOT NULL,
    alert_count     int           NOT NULL,
    first_seen_utc  datetime2(3)  NOT NULL,
    last_seen_utc   datetime2(3)  NOT NULL,
    CONSTRAINT PK_daily_alert_summary PRIMARY KEY (summary_date, agent_id, rule_id, rule_level)
);
GO

IF OBJECT_ID(N'sg.daily_technique_summary') IS NULL
CREATE TABLE sg.daily_technique_summary (
    summary_date  date         NOT NULL,
    agent_id      varchar(16)  NOT NULL,
    technique_id  varchar(16)  NOT NULL,
    alert_count   int          NOT NULL,
    CONSTRAINT PK_daily_technique_summary PRIMARY KEY (summary_date, agent_id, technique_id)
);
GO

-- Rebuild summaries for every local date on or after @from_date that still has detail rows.
CREATE OR ALTER PROCEDURE sg.refresh_daily_summary
    @from_date date = NULL   -- NULL = the last 3 local days
AS
BEGIN
    SET NOCOUNT ON;
    IF @from_date IS NULL
        SET @from_date = DATEADD(day, -2, CAST(SYSDATETIMEOFFSET() AT TIME ZONE 'Eastern Standard Time' AS date));

    DECLARE @a TABLE (doc_id varchar(64) PRIMARY KEY, d date, agent_id varchar(16), rule_id int,
                      rule_level tinyint, ts datetime2(3));
    INSERT INTO @a
    SELECT doc_id, CAST(alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS date),
           agent_id, rule_id, rule_level, alert_ts_utc
    FROM sg.alerts
    WHERE alert_ts_utc >= DATEADD(day, -1, CAST(@from_date AS datetime2(3)));   -- covers the time zone offset
    DELETE FROM @a WHERE d < @from_date;

    BEGIN TRANSACTION;
    DELETE s FROM sg.daily_alert_summary AS s WHERE s.summary_date IN (SELECT DISTINCT d FROM @a);
    INSERT INTO sg.daily_alert_summary (summary_date, agent_id, rule_id, rule_level, alert_count, first_seen_utc, last_seen_utc)
    SELECT d, agent_id, rule_id, rule_level, COUNT(*), MIN(ts), MAX(ts)
    FROM @a GROUP BY d, agent_id, rule_id, rule_level;

    DELETE s FROM sg.daily_technique_summary AS s WHERE s.summary_date IN (SELECT DISTINCT d FROM @a);
    INSERT INTO sg.daily_technique_summary (summary_date, agent_id, technique_id, alert_count)
    SELECT a.d, a.agent_id, t.technique_id, COUNT(*)
    FROM @a AS a JOIN sg.alert_techniques AS t ON t.doc_id = a.doc_id
    GROUP BY a.d, a.agent_id, t.technique_id;
    COMMIT;
END;
GO

-- Trim, then delete, Low-severity detail. Medium and above is never touched.
CREATE OR ALTER PROCEDURE sg.apply_retention
    @low_full_detail_days int = 365,
    @low_keep_days        int = NULL   -- NULL = never delete Low rows
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @now datetime2(3) = SYSUTCDATETIME();

    UPDATE sg.alerts SET raw_json = NULL
    WHERE rule_level < 7 AND raw_json IS NOT NULL
      AND alert_ts_utc < DATEADD(day, -@low_full_detail_days, @now);
    DECLARE @trimmed int = @@ROWCOUNT;

    -- Only delete days that already have a summary row, so no history is lost.
    DECLARE @deleted int = 0;
    IF @low_keep_days IS NOT NULL
    BEGIN
    DELETE a FROM sg.alerts AS a
    WHERE a.rule_level < 7
      AND a.alert_ts_utc < DATEADD(day, -@low_keep_days, @now)
      AND EXISTS (SELECT 1 FROM sg.daily_alert_summary AS s
                  WHERE s.summary_date = CAST(a.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS date)
                    AND s.agent_id = a.agent_id AND s.rule_id = a.rule_id);
    SET @deleted = @@ROWCOUNT;
    END;

    SELECT @trimmed AS low_alerts_trimmed, @deleted AS low_alerts_deleted;
END;
GO

-- Long-term trend views for Power BI: complete history even after detail retention.
CREATE OR ALTER VIEW rpt.daily_alert_trend AS
SELECT
    s.summary_date,
    ag.agent_name,
    s.rule_id,
    r.description AS rule_description,
    s.rule_level,
    CASE WHEN s.rule_level >= 15 THEN 'Critical'
         WHEN s.rule_level >= 12 THEN 'High'
         WHEN s.rule_level >= 7  THEN 'Medium'
         ELSE 'Low' END AS severity_band,
    CASE WHEN s.rule_level >= 15 THEN 1
         WHEN s.rule_level >= 12 THEN 2
         WHEN s.rule_level >= 7  THEN 3
         ELSE 4 END AS severity_sort,
    s.alert_count
FROM sg.daily_alert_summary AS s
JOIN sg.agents AS ag ON ag.agent_id = s.agent_id
JOIN sg.rules  AS r  ON r.rule_id  = s.rule_id;
GO

CREATE OR ALTER VIEW rpt.daily_technique_trend AS
SELECT
    s.summary_date,
    ag.agent_name,
    s.technique_id,
    t.technique_name,
    CONCAT(s.technique_id, ' ', t.technique_name) AS technique_label,
    s.alert_count
FROM sg.daily_technique_summary AS s
JOIN sg.agents           AS ag ON ag.agent_id = s.agent_id
JOIN sg.mitre_techniques AS t  ON t.technique_id = s.technique_id;
GO
