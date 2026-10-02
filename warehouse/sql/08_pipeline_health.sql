-- Watchtide warehouse: pipeline health for the Power BI "Pipeline Health" page.
-- Answers: is data arriving, how late is it, does the loader fail, and how
-- close is the warehouse to its 100 GB cap. Figures are as of the moment
-- Power BI refreshes. Safe to re-run.

USE SentinelGridWarehouse;
GO

-- Time from a Wazuh alert to its row in SQL, per hour of loading. The first
-- successful run backfilled history, so alerts it loaded are excluded.
CREATE OR ALTER VIEW rpt.ingest_latency_hourly AS
WITH loads AS (
    SELECT
        DATEADD(hour, DATEDIFF(hour, 0, CAST(a.loaded_at_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0))), 0)
            AS loaded_hour_local,
        DATEDIFF(second, a.alert_ts_utc, a.loaded_at_utc) / 60.0 AS latency_minutes
    FROM sg.alerts AS a
    WHERE a.loaded_at_utc >= DATEADD(day, -14, SYSUTCDATETIME())
      AND a.loaded_at_utc > (SELECT MIN(finished_at_utc) FROM sg.load_runs WHERE status = 'succeeded')
)
SELECT DISTINCT
    loaded_hour_local,
    COUNT(*) OVER (PARTITION BY loaded_hour_local) AS alerts_loaded,
    CAST(PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY latency_minutes) OVER (PARTITION BY loaded_hour_local) AS decimal(9, 1)) AS p50_minutes,
    CAST(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_minutes) OVER (PARTITION BY loaded_hour_local) AS decimal(9, 1)) AS p95_minutes,
    CAST(MAX(latency_minutes) OVER (PARTITION BY loaded_hour_local) AS decimal(9, 1)) AS max_minutes
FROM loads;
GO

-- One row: the pipeline's vital signs at refresh time.
CREATE OR ALTER VIEW rpt.pipeline_status AS
WITH runs AS (
    SELECT
        MAX(CASE WHEN status = 'succeeded' THEN finished_at_utc END)                                  AS last_success_utc,
        SUM(CASE WHEN started_at_utc >= DATEADD(hour, -24, SYSUTCDATETIME()) THEN 1 ELSE 0 END)        AS runs_24h,
        SUM(CASE WHEN started_at_utc >= DATEADD(hour, -24, SYSUTCDATETIME()) AND status = 'failed' THEN 1 ELSE 0 END)
                                                                                                         AS failed_runs_24h,
        SUM(CASE WHEN started_at_utc >= DATEADD(day, -7, SYSUTCDATETIME()) THEN 1 ELSE 0 END)          AS runs_7d,
        SUM(CASE WHEN started_at_utc >= DATEADD(day, -7, SYSUTCDATETIME()) AND status = 'succeeded' THEN 1 ELSE 0 END)
                                                                                                         AS succeeded_runs_7d,
        SUM(CASE WHEN started_at_utc >= DATEADD(hour, -24, SYSUTCDATETIME()) THEN alerts_inserted ELSE 0 END)
                                                                                                         AS alerts_loaded_24h,
        COUNT(*)                                                                                         AS runs_all_time
    FROM sg.load_runs
),
latency AS (
    SELECT DISTINCT
        PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY DATEDIFF(second, alert_ts_utc, loaded_at_utc)) OVER () / 60.0 AS p50,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY DATEDIFF(second, alert_ts_utc, loaded_at_utc)) OVER () / 60.0 AS p95
    FROM sg.alerts
    WHERE loaded_at_utc >= DATEADD(day, -7, SYSUTCDATETIME())
      AND loaded_at_utc > (SELECT MIN(finished_at_utc) FROM sg.load_runs WHERE status = 'succeeded')
),
storage AS (
    SELECT
        SUM(CASE WHEN type_desc = 'ROWS' THEN CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint) * 8 / 1024.0 END) AS data_used_mb,
        MAX(CASE WHEN type_desc = 'ROWS' AND max_size > 0 THEN CAST(max_size AS bigint) * 8 / 1024.0 END)         AS data_cap_mb
    FROM sys.database_files
)
SELECT
    CAST(SYSUTCDATETIME() AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0))                   AS as_of_local,
    CAST(r.last_success_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0))                 AS last_success_local,
    DATEDIFF(minute, r.last_success_utc, SYSUTCDATETIME())                                                            AS minutes_since_success,
    CAST((SELECT MAX(alert_ts_utc) FROM sg.alerts) AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0))
                                                                                                                      AS newest_alert_local,
    DATEDIFF(minute, (SELECT MAX(alert_ts_utc) FROM sg.alerts), SYSUTCDATETIME())                                     AS minutes_since_newest_alert,
    r.runs_24h,
    r.failed_runs_24h,
    CAST(100.0 * r.succeeded_runs_7d / NULLIF(r.runs_7d, 0) AS decimal(5, 1))                                         AS success_rate_7d_pct,
    r.alerts_loaded_24h,
    r.runs_all_time,
    CAST(l.p50 AS decimal(9, 1))                                                                                      AS latency_p50_minutes_7d,
    CAST(l.p95 AS decimal(9, 1))                                                                                      AS latency_p95_minutes_7d,
    (SELECT COUNT_BIG(*) FROM sg.alerts)                                                                              AS alert_rows,
    CAST(s.data_used_mb AS decimal(12, 1))                                                                            AS data_used_mb,
    CAST(s.data_cap_mb AS decimal(12, 1))                                                                             AS data_cap_mb
FROM runs AS r
CROSS JOIN storage AS s
LEFT JOIN latency AS l ON 1 = 1;
GO
