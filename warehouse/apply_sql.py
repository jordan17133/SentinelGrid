"""Apply the SentinelGrid warehouse SQL scripts in order.

Usage (from the repo root):
    .venv\\Scripts\\python.exe warehouse\\apply_sql.py

Connects with Windows authentication to the local default SQL Server instance.
Every script is idempotent, so re-running is safe.
"""

import re
import sys
from pathlib import Path

import pyodbc

SQL_DIR = Path(__file__).parent / "sql"
CONN_STR = (
    "Driver={ODBC Driver 18 for SQL Server};Server=localhost;Database=master;"
    "Trusted_Connection=yes;TrustServerCertificate=yes"
)
BATCH_SEPARATOR = re.compile(r"^\s*GO\s*$", re.IGNORECASE | re.MULTILINE)


def main() -> int:
    conn = pyodbc.connect(CONN_STR, autocommit=True)
    cursor = conn.cursor()
    for script in sorted(SQL_DIR.glob("*.sql")):
        batches = [b for b in BATCH_SEPARATOR.split(script.read_text(encoding="utf-8-sig")) if b.strip()]
        for batch in batches:
            cursor.execute(batch)
            while cursor.nextset():
                pass
        print(f"applied {script.name} ({len(batches)} batches)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
