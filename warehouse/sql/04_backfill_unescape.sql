-- One-time cleanup for rows loaded before the loader unescaped Windows paths.
-- Wazuh keeps JSON escaping inside eventdata strings (C:\\Windows, \"quoted\"),
-- so the first loads stored doubled backslashes. Mirrors unescape() in
-- loader/wazuh_to_sql.py. Safe to re-run: rows already clean are left alone.

USE SentinelGridWarehouse;
GO

UPDATE sg.alerts
SET process_image   = REPLACE(REPLACE(process_image,   '\\', '\'), '\"', '"'),
    parent_image    = REPLACE(REPLACE(parent_image,    '\\', '\'), '\"', '"'),
    command_line    = REPLACE(REPLACE(command_line,    '\\', '\'), '\"', '"'),
    target_filename = REPLACE(REPLACE(target_filename, '\\', '\'), '\"', '"'),
    user_name       = REPLACE(REPLACE(user_name,       '\\', '\'), '\"', '"')
WHERE process_image   LIKE '%\\%' OR parent_image LIKE '%\\%' OR command_line LIKE '%\\%'
   OR target_filename LIKE '%\\%' OR user_name    LIKE '%\\%'
   OR command_line    LIKE '%\"%';
GO

-- Some rule descriptions embed event fields (e.g. rule 92036 "A C:\\Windows\\...\\net.exe
-- binary was started..."), so they carried the same escaping until the loader
-- unescaped descriptions too.
UPDATE sg.alerts
SET rule_description = REPLACE(REPLACE(rule_description, '\\', '\'), '\"', '"')
WHERE rule_description LIKE '%\\%' OR rule_description LIKE '%\"%';
GO
UPDATE sg.rules
SET description = REPLACE(REPLACE(description, '\\', '\'), '\"', '"')
WHERE description LIKE '%\\%' OR description LIKE '%\"%';
GO
