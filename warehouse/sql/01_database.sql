-- SentinelGrid warehouse: instance settings and database.
-- Runs against master. Safe to re-run.

-- The Wazuh VM already reserves 8 GB of host RAM, so cap SQL Server at 4 GB.
EXEC sys.sp_configure N'show advanced options', 1;
RECONFIGURE;
EXEC sys.sp_configure N'max server memory (MB)', 4096;
RECONFIGURE;
GO

IF DB_ID(N'SentinelGridWarehouse') IS NULL
    CREATE DATABASE SentinelGridWarehouse;
GO

-- Lab database: no point-in-time restore needed, so keep the log small.
ALTER DATABASE SentinelGridWarehouse SET RECOVERY SIMPLE;
GO
