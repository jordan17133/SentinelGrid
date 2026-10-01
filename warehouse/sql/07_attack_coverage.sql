-- SentinelGrid warehouse: MITRE ATT&CK coverage.
--
-- Three different questions, kept apart on purpose:
--   1. Which techniques does ATT&CK define for the platforms monitored here?  (catalog)
--   2. Which of them could Wazuh alert on, given the rules deployed and the     (rule map)
--      data sources this lab actually collects?
--   3. Which ones actually fired here, how often, and was it triaged?          (alerts)
-- A technique that fired is not an attack: most activity here is benign and
-- triaged. Proving that a rule catches a real technique needs attack
-- simulations, which are a later stage.
--
-- The catalog and rule map come from the Wazuh server
-- (wazuh/manager/export_attack_catalog.py) and are loaded by
-- warehouse/load_attack_catalog.py. Until then, only question 3 has data.
-- Safe to re-run.

USE SentinelGridWarehouse;
GO

IF OBJECT_ID(N'sg.attack_tactics') IS NULL
CREATE TABLE sg.attack_tactics (
    tactic_id     varchar(16)   NOT NULL CONSTRAINT PK_attack_tactics PRIMARY KEY,   -- TA0002
    tactic_name   nvarchar(64)  NOT NULL,                                            -- Execution
    matrix_order  tinyint       NOT NULL                                             -- left to right in the Enterprise matrix
);
GO
MERGE sg.attack_tactics AS t
USING (VALUES
    ('TA0043', N'Reconnaissance', 1),        ('TA0042', N'Resource Development', 2),
    ('TA0001', N'Initial Access', 3),        ('TA0002', N'Execution', 4),
    ('TA0003', N'Persistence', 5),           ('TA0004', N'Privilege Escalation', 6),
    ('TA0005', N'Defense Evasion', 7),       ('TA0006', N'Credential Access', 8),
    ('TA0007', N'Discovery', 9),             ('TA0008', N'Lateral Movement', 10),
    ('TA0009', N'Collection', 11),           ('TA0011', N'Command and Control', 12),
    ('TA0010', N'Exfiltration', 13),         ('TA0040', N'Impact', 14)
) AS s (tactic_id, tactic_name, matrix_order)
ON t.tactic_id = s.tactic_id
WHEN MATCHED THEN UPDATE SET tactic_name = s.tactic_name, matrix_order = s.matrix_order
WHEN NOT MATCHED THEN INSERT (tactic_id, tactic_name, matrix_order) VALUES (s.tactic_id, s.tactic_name, s.matrix_order);
GO

-- ATT&CK techniques and sub-techniques from Wazuh's bundled catalog.
IF OBJECT_ID(N'sg.attack_catalog') IS NULL
CREATE TABLE sg.attack_catalog (
    technique_id         varchar(16)    NOT NULL CONSTRAINT PK_attack_catalog PRIMARY KEY,   -- T1059.001
    technique_name       nvarchar(256)  NOT NULL,
    parent_technique_id  varchar(16)    NULL,
    platforms            nvarchar(256)  NULL,   -- comma-separated, e.g. Windows,Linux,macOS
    is_active            bit            NOT NULL -- false when deprecated or revoked
);
GO
IF OBJECT_ID(N'sg.attack_catalog_tactics') IS NULL
CREATE TABLE sg.attack_catalog_tactics (
    technique_id  varchar(16)  NOT NULL,
    tactic_id     varchar(16)  NOT NULL,
    CONSTRAINT PK_attack_catalog_tactics PRIMARY KEY (technique_id, tactic_id)
);
GO

-- Deployed Wazuh rules and the techniques they are tagged with.
-- collected_here: the rule's data source is one this lab sends to Wazuh.
IF OBJECT_ID(N'sg.rule_attack_map') IS NULL
CREATE TABLE sg.rule_attack_map (
    rule_id         int            NOT NULL,
    technique_id    varchar(16)    NOT NULL,
    rule_level      tinyint        NOT NULL,
    description     nvarchar(512)  NOT NULL,
    rule_file       nvarchar(128)  NOT NULL,
    source_family   varchar(32)    NOT NULL,
    collected_here  bit            NOT NULL,
    CONSTRAINT PK_rule_attack_map PRIMARY KEY (rule_id, technique_id)
);
GO

-- Provenance of the catalog and rule map currently loaded.
IF OBJECT_ID(N'sg.attack_catalog_loads') IS NULL
CREATE TABLE sg.attack_catalog_loads (
    load_id           int IDENTITY(1, 1) NOT NULL CONSTRAINT PK_attack_catalog_loads PRIMARY KEY,
    loaded_at_utc     datetime2(0)  NOT NULL,
    exported_at_utc   datetime2(0)  NULL,
    wazuh_version     varchar(32)   NULL,
    attack_version    varchar(32)   NULL,
    techniques        int           NOT NULL,
    rules_with_attack int           NOT NULL
);
GO

-- Rules whose alerts were investigated, with the outcome. Curated by hand from triage/.
IF OBJECT_ID(N'sg.rule_triage') IS NULL
CREATE TABLE sg.rule_triage (
    rule_id      int            NOT NULL CONSTRAINT PK_rule_triage PRIMARY KEY,
    verdict      nvarchar(128)  NOT NULL,
    report_path  nvarchar(256)  NOT NULL
);
GO
MERGE sg.rule_triage AS t
USING (VALUES
    (92213, N'Benign: installers, watchdogs (tuned to 100100), AMD crash reporter, build tooling Add-Type',
            N'triage/2026-10-01-rules-92213-92217-after-tuning.md'),
    (92217, N'Benign: software installs and updates (SQL Server, .NET, AMD, Logitech)',
            N'triage/2026-10-01-rules-92213-92217-after-tuning.md'),
    (92058, N'Benign: Windows compatibility maintenance (tuned to 100101)',
            N'triage/2026-09-30-rule-92058-sdbinst-pca-maintenance.md'),
    (5710,  N'True positive: controlled password-guessing test',
            N'triage/2026-10-01-ssh-failed-logins-wazuh-server.md'),
    (5503,  N'True positive: controlled password-guessing test',
            N'triage/2026-10-01-ssh-failed-logins-wazuh-server.md'),
    (5760,  N'True positive: controlled password-guessing test',
            N'triage/2026-10-01-ssh-failed-logins-wazuh-server.md'),
    (2502,  N'True positive: controlled password-guessing test',
            N'triage/2026-10-01-ssh-failed-logins-wazuh-server.md'),
    (91823, N'Benign: Windows troubleshooter library (same second as SDIAG scripts)',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (100110, N'Benign: planned FIM rule test file in .ssh',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (91809, N'Benign: build tooling base64 command wrapper (kept visible on purpose)',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (60227, N'Benign: the user''s USB headset',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (60182, N'Benign: SQL Server setup added a service account',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (5902, N'Benign: Wazuh install created wazuh-dashboard',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (750, N'Benign: Windows state keys (bam, W32Time)',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (751, N'Benign: Firefox removal during posture work',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92052, N'Benign: build tooling shells and AMD software',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92032, N'Benign: build tooling shells',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92021, N'Benign: Wazuh CIS checks cleaning up temp files',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92066, N'Benign: Wazuh CIS checks running secedit',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (91816, N'Benign: Wazuh CIS checks and build tooling',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (91815, N'Benign: build tooling process checks',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92200, N'Benign: desktop apps and build scripts',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92307, N'Benign: service installs during software setup',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (5501, N'Benign: admin SSH sessions and loader tunnel',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (5715, N'Benign: admin SSH sessions and loader tunnel',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (5402, N'Benign: Wazuh server administration',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (67028, N'Benign: normal Windows and service logons',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (506, N'Benign: planned agent restarts',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92036, N'Benign: planned agent restart',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (92006, N'Benign: build tooling Add-Type (kept Critical on purpose)',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (91819, N'Benign: build tooling and Windows troubleshooter',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (91820, N'Benign: Windows troubleshooter',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (60669, N'Benign: planned restarts',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (67018, N'Benign: planned restarts',
            N'triage/2026-10-01-baseline-review-remaining-rules.md'),
    (67017, N'Low risk: loopback admin share by own account, source process not confirmed',
            N'triage/2026-10-01-baseline-review-remaining-rules.md')
) AS s (rule_id, verdict, report_path)
ON t.rule_id = s.rule_id
WHEN MATCHED THEN UPDATE SET verdict = s.verdict, report_path = s.report_path
WHEN NOT MATCHED THEN INSERT (rule_id, verdict, report_path) VALUES (s.rule_id, s.verdict, s.report_path);
GO

-- Question 3: every technique that fired, with the rule behind most of it.
CREATE OR ALTER VIEW rpt.attack_observed AS
WITH per_rule AS (
    SELECT t.technique_id, a.rule_id, COUNT(*) AS alerts, MAX(a.rule_level) AS max_level,
           MIN(a.alert_ts_utc) AS first_utc, MAX(a.alert_ts_utc) AS last_utc
    FROM sg.alert_techniques AS t
    JOIN sg.alerts AS a ON a.doc_id = t.doc_id
    GROUP BY t.technique_id, a.rule_id
),
per_technique AS (
    SELECT technique_id, SUM(alerts) AS alerts, COUNT(*) AS rules_fired, MAX(max_level) AS max_level,
           MIN(first_utc) AS first_utc, MAX(last_utc) AS last_utc
    FROM per_rule
    GROUP BY technique_id
),
top_rule AS (
    SELECT technique_id, rule_id, alerts,
           ROW_NUMBER() OVER (PARTITION BY technique_id ORDER BY alerts DESC, rule_id) AS rn
    FROM per_rule
),
tactics AS (
    SELECT ct.technique_id,
           STRING_AGG(ta.tactic_name, N', ') WITHIN GROUP (ORDER BY ta.matrix_order) AS tactic_names,
           MIN(ta.matrix_order) AS first_tactic_order
    FROM sg.attack_catalog_tactics AS ct
    JOIN sg.attack_tactics AS ta ON ta.tactic_id = ct.tactic_id
    GROUP BY ct.technique_id
)
SELECT
    p.technique_id,
    m.technique_name,
    CONCAT(p.technique_id, ' ', m.technique_name) AS technique_label,
    ISNULL(tc.tactic_names, N'(catalog not loaded)') AS tactic_names,
    ISNULL(tc.first_tactic_order, 99) AS first_tactic_order,
    p.alerts,
    p.rules_fired,
    p.max_level,
    CAST(p.first_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS first_seen_local,
    CAST(p.last_utc  AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS last_seen_local,
    tr.rule_id AS top_rule_id,
    r.description AS top_rule_description,
    CAST(100.0 * tr.alerts / p.alerts AS decimal(4, 1)) AS top_rule_share_pct,
    ISNULL(rt.verdict, N'Not triaged') AS top_rule_triage
FROM per_technique AS p
JOIN sg.mitre_techniques AS m ON m.technique_id = p.technique_id
JOIN top_rule AS tr ON tr.technique_id = p.technique_id AND tr.rn = 1
JOIN sg.rules AS r ON r.rule_id = tr.rule_id
LEFT JOIN tactics AS tc ON tc.technique_id = p.technique_id
LEFT JOIN sg.rule_triage AS rt ON rt.rule_id = tr.rule_id;
GO

-- Questions 1-3 together: one row per technique and tactic for the platforms
-- monitored here (Windows and Linux), active techniques only.
CREATE OR ALTER VIEW rpt.attack_coverage AS
WITH rules AS (
    SELECT technique_id,
           COUNT(DISTINCT CASE WHEN collected_here = 1 THEN rule_id END) AS rules_collected,
           COUNT(DISTINCT rule_id) AS rules_any
    FROM sg.rule_attack_map
    GROUP BY technique_id
),
observed AS (
    SELECT t.technique_id, COUNT(*) AS alerts, MAX(a.alert_ts_utc) AS last_utc
    FROM sg.alert_techniques AS t
    JOIN sg.alerts AS a ON a.doc_id = t.doc_id
    GROUP BY t.technique_id
)
SELECT
    c.technique_id,
    c.technique_name,
    CONCAT(c.technique_id, ' ', c.technique_name) AS technique_label,
    CASE WHEN c.parent_technique_id IS NULL THEN 0 ELSE 1 END AS is_subtechnique,
    ta.tactic_name,
    ta.matrix_order,
    ISNULL(r.rules_collected, 0) AS rules_collected,
    ISNULL(r.rules_any, 0) AS rules_any,
    ISNULL(o.alerts, 0) AS alerts,
    CAST(o.last_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS last_seen_local,
    CASE WHEN o.alerts > 0              THEN 'Fired here'
         WHEN r.rules_collected > 0     THEN 'Rule ready, not fired'
         WHEN r.rules_any > 0           THEN 'Rule exists, source not collected'
         ELSE 'No Wazuh rule' END AS coverage_status,
    CASE WHEN o.alerts > 0              THEN 1
         WHEN r.rules_collected > 0     THEN 2
         WHEN r.rules_any > 0           THEN 3
         ELSE 4 END AS coverage_sort
FROM sg.attack_catalog AS c
JOIN sg.attack_catalog_tactics AS ct ON ct.technique_id = c.technique_id
JOIN sg.attack_tactics AS ta ON ta.tactic_id = ct.tactic_id
LEFT JOIN rules AS r ON r.technique_id = c.technique_id
LEFT JOIN observed AS o ON o.technique_id = c.technique_id
WHERE c.is_active = 1
  AND (c.platforms LIKE N'%Windows%' OR c.platforms LIKE N'%Linux%');
GO

-- The catalog version behind the coverage figures, for the page footer.
CREATE OR ALTER VIEW rpt.attack_catalog_info AS
SELECT TOP 1
    CAST(loaded_at_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(0)) AS loaded_at_local,
    exported_at_utc, wazuh_version, attack_version, techniques, rules_with_attack
FROM sg.attack_catalog_loads
ORDER BY load_id DESC;
GO
