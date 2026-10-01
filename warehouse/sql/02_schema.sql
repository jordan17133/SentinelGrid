-- SentinelGrid warehouse: core tables.
-- Raw, high-volume telemetry stays in the Wazuh Indexer. This database holds
-- curated alerts, their dimensions, vulnerability snapshots and load history.
-- Safe to re-run: every object is created only if it is missing.

USE SentinelGridWarehouse;
GO

IF SCHEMA_ID(N'sg') IS NULL EXEC (N'CREATE SCHEMA sg');
GO
IF SCHEMA_ID(N'rpt') IS NULL EXEC (N'CREATE SCHEMA rpt');
GO

-- Dimension: monitored endpoints.
IF OBJECT_ID(N'sg.agents') IS NULL
CREATE TABLE sg.agents (
    agent_id        varchar(16)   NOT NULL CONSTRAINT PK_agents PRIMARY KEY,
    agent_name      nvarchar(128) NOT NULL,
    agent_ip        varchar(64)   NULL,
    first_seen_utc  datetime2(3)  NOT NULL,
    last_seen_utc   datetime2(3)  NOT NULL
);
GO

-- Dimension: Wazuh detection rules, keeping the latest description and level seen.
IF OBJECT_ID(N'sg.rules') IS NULL
CREATE TABLE sg.rules (
    rule_id         int            NOT NULL CONSTRAINT PK_rules PRIMARY KEY,
    description     nvarchar(512)  NOT NULL,
    rule_level      tinyint        NOT NULL,
    rule_groups     nvarchar(512)  NULL,
    first_seen_utc  datetime2(3)   NOT NULL,
    last_seen_utc   datetime2(3)   NOT NULL
);
GO

-- Dimension: MITRE ATT&CK techniques referenced by alerts.
IF OBJECT_ID(N'sg.mitre_techniques') IS NULL
CREATE TABLE sg.mitre_techniques (
    technique_id    varchar(16)   NOT NULL CONSTRAINT PK_mitre_techniques PRIMARY KEY,
    technique_name  nvarchar(256) NOT NULL
);
GO

-- Fact: one row per Wazuh alert. doc_id is the Indexer document _id, so every
-- row traces back to exactly one record in wazuh-alerts-*.
IF OBJECT_ID(N'sg.alerts') IS NULL
CREATE TABLE sg.alerts (
    doc_id            varchar(64)    NOT NULL CONSTRAINT PK_alerts PRIMARY KEY,
    index_name        varchar(128)   NOT NULL,
    wazuh_alert_id    varchar(64)    NULL,
    alert_ts_utc      datetime2(3)   NOT NULL,
    agent_id          varchar(16)    NOT NULL,
    rule_id           int            NOT NULL,
    rule_level        tinyint        NOT NULL,
    rule_description  nvarchar(512)  NOT NULL,
    event_channel     nvarchar(128)  NULL,
    win_event_id      int            NULL,
    process_image     nvarchar(1024) NULL,
    parent_image      nvarchar(1024) NULL,
    command_line      nvarchar(max)  NULL,
    target_filename   nvarchar(1024) NULL,
    user_name         nvarchar(256)  NULL,
    raw_json          nvarchar(max)  NOT NULL,
    loaded_at_utc     datetime2(3)   NOT NULL CONSTRAINT DF_alerts_loaded DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_alerts_agent FOREIGN KEY (agent_id) REFERENCES sg.agents (agent_id),
    CONSTRAINT FK_alerts_rule  FOREIGN KEY (rule_id)  REFERENCES sg.rules (rule_id)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_alerts_ts' AND object_id = OBJECT_ID(N'sg.alerts'))
    CREATE INDEX IX_alerts_ts ON sg.alerts (alert_ts_utc) INCLUDE (agent_id, rule_id, rule_level);
GO

-- Bridge tables: an alert can map to several techniques and tactics.
IF OBJECT_ID(N'sg.alert_techniques') IS NULL
CREATE TABLE sg.alert_techniques (
    doc_id        varchar(64) NOT NULL,
    technique_id  varchar(16) NOT NULL,
    CONSTRAINT PK_alert_techniques PRIMARY KEY (doc_id, technique_id),
    CONSTRAINT FK_alert_techniques_alert FOREIGN KEY (doc_id) REFERENCES sg.alerts (doc_id) ON DELETE CASCADE,
    CONSTRAINT FK_alert_techniques_tech  FOREIGN KEY (technique_id) REFERENCES sg.mitre_techniques (technique_id)
);
GO
IF OBJECT_ID(N'sg.alert_tactics') IS NULL
CREATE TABLE sg.alert_tactics (
    doc_id  varchar(64)   NOT NULL,
    tactic  nvarchar(64)  NOT NULL,
    CONSTRAINT PK_alert_tactics PRIMARY KEY (doc_id, tactic),
    CONSTRAINT FK_alert_tactics_alert FOREIGN KEY (doc_id) REFERENCES sg.alerts (doc_id) ON DELETE CASCADE
);
GO

-- Snapshot: vulnerability state per agent, captured once per day, so Power BI
-- can show findings going down as software is patched or removed.
IF OBJECT_ID(N'sg.vulnerability_snapshots') IS NULL
CREATE TABLE sg.vulnerability_snapshots (
    snapshot_date     date           NOT NULL,
    agent_id          varchar(16)    NOT NULL,
    cve_id            varchar(32)    NOT NULL,
    package_name      nvarchar(256)  NOT NULL,
    package_version   nvarchar(128)  NOT NULL,
    severity          varchar(16)    NOT NULL,
    base_score        decimal(3, 1)  NULL,
    detected_at_utc   datetime2(3)   NULL,
    CONSTRAINT PK_vulnerability_snapshots PRIMARY KEY (snapshot_date, agent_id, cve_id, package_name, package_version)
);
GO

-- Audit: one row per loader run.
IF OBJECT_ID(N'sg.load_runs') IS NULL
CREATE TABLE sg.load_runs (
    run_id            int IDENTITY(1, 1) NOT NULL CONSTRAINT PK_load_runs PRIMARY KEY,
    started_at_utc    datetime2(3)  NOT NULL,
    finished_at_utc   datetime2(3)  NULL,
    status            varchar(16)   NOT NULL,
    watermark_from    datetime2(3)  NULL,
    watermark_to      datetime2(3)  NULL,
    alerts_fetched    int           NOT NULL CONSTRAINT DF_load_runs_fetched DEFAULT 0,
    alerts_inserted   int           NOT NULL CONSTRAINT DF_load_runs_inserted DEFAULT 0,
    vulns_snapshotted int           NOT NULL CONSTRAINT DF_load_runs_vulns DEFAULT 0,
    error_message     nvarchar(max) NULL
);
GO

-- Power BI connects through this role, which can read reporting views only.
IF DATABASE_PRINCIPAL_ID(N'rpt_reader') IS NULL
    CREATE ROLE rpt_reader;
GO
GRANT SELECT ON SCHEMA::rpt TO rpt_reader;
GO
