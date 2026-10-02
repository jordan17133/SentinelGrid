-- Watchtide warehouse: least-privilege reporting access.
-- SQL Server stays in Windows-authentication-only mode, so there is no SQL
-- password to steal. Reporting tools get the rpt_reader role (SELECT on the
-- rpt schema only). powerbi_reader is a user without a login: it cannot sign
-- in, and exists so the role can be tested with EXECUTE AS. A real reporting
-- account (a Windows or Entra identity) is added to the same role.

USE SentinelGridWarehouse;
GO

IF DATABASE_PRINCIPAL_ID(N'powerbi_reader') IS NULL
    CREATE USER powerbi_reader WITHOUT LOGIN;
GO
IF IS_ROLEMEMBER(N'rpt_reader', N'powerbi_reader') = 0
    ALTER ROLE rpt_reader ADD MEMBER powerbi_reader;
GO
