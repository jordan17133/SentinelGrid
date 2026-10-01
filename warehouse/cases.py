"""Open, assign, annotate and close SentinelGrid cases.

Usage (from the repo root):
    .venv\\Scripts\\python.exe warehouse\\cases.py list
    .venv\\Scripts\\python.exe warehouse\\cases.py open "Title" --severity High --rules 5710,5760 [--assign Jordan]
    .venv\\Scripts\\python.exe warehouse\\cases.py assign 7 Jordan
    .venv\\Scripts\\python.exe warehouse\\cases.py note 7 "Checked the parent process"
    .venv\\Scripts\\python.exe warehouse\\cases.py close 7 --verdict "True positive" --report triage/<file>.md

Every change is written to sg.cases and recorded in sg.case_events, so each
case keeps its full history. The first alert time is looked up from the
case's rules in sg.alerts.
"""

import argparse
import getpass
import sys

import pyodbc

CONN_STR = (
    "Driver={ODBC Driver 18 for SQL Server};Server=localhost;Database=SentinelGridWarehouse;"
    "Trusted_Connection=yes;TrustServerCertificate=yes"
)
ACTOR = getpass.getuser()


def log(cur, case_id: int, action: str, detail: str | None) -> None:
    cur.execute("INSERT INTO sg.case_events (case_id, action, actor, detail) VALUES (?, ?, ?, ?)",
                case_id, action, ACTOR, detail)


def require_case(cur, case_id: int) -> str:
    row = cur.execute("SELECT status FROM sg.cases WHERE case_id = ?", case_id).fetchone()
    if not row:
        raise SystemExit(f"no case {case_id}")
    return row.status


def cmd_list(cur, _args) -> None:
    rows = cur.execute("SELECT case_number, status, severity, verdict, hours_to_verdict, open_age_hours, title"
                       " FROM rpt.cases ORDER BY CASE WHEN status = 'Closed' THEN 1 ELSE 0 END, case_id").fetchall()
    for r in rows:
        timing = f"{r.hours_to_verdict}h to verdict" if r.hours_to_verdict is not None else f"open {r.open_age_hours}h"
        print(f"{r.case_number}  {r.status:11} {r.severity:8} {r.verdict:13} {timing:20} {r.title}")


def cmd_open(cur, args) -> None:
    rules = [int(r) for r in args.rules.split(",")]
    marks = ",".join("?" * len(rules))
    first = cur.execute(f"SELECT MIN(alert_ts_utc) FROM sg.alerts WHERE rule_id IN ({marks})", *rules).fetchone()[0]
    if first is None:
        raise SystemExit("no alerts found for those rules; check the rule IDs")
    key = f"{first:%Y-%m-%d}-{rules[0]}-{args.title[:30].lower().replace(' ', '-')}"
    case_id = cur.execute(
        "INSERT INTO sg.cases (case_key, title, severity, status, assigned_to, first_alert_utc, opened_utc)"
        " OUTPUT INSERTED.case_id VALUES (?, ?, ?, ?, ?, ?, SYSUTCDATETIME())",
        key, args.title, args.severity, "In progress" if args.assign else "Open", args.assign, first).fetchone()[0]
    cur.executemany("INSERT INTO sg.case_rules (case_id, rule_id) VALUES (?, ?)", [(case_id, r) for r in rules])
    log(cur, case_id, "Opened", f"rules {args.rules}")
    if args.assign:
        log(cur, case_id, "Assigned", args.assign)
    print(f"opened SG-{case_id:03d}")


def cmd_assign(cur, args) -> None:
    if require_case(cur, args.case_id) == "Closed":
        raise SystemExit("case is closed")
    cur.execute("UPDATE sg.cases SET assigned_to = ?, status = 'In progress' WHERE case_id = ?", args.who, args.case_id)
    log(cur, args.case_id, "Assigned", args.who)


def cmd_note(cur, args) -> None:
    require_case(cur, args.case_id)
    log(cur, args.case_id, "Note", args.text)


def cmd_close(cur, args) -> None:
    if require_case(cur, args.case_id) == "Closed":
        raise SystemExit("case is already closed")
    cur.execute("UPDATE sg.cases SET status = 'Closed', verdict = ?, closed_utc = SYSUTCDATETIME(),"
                " report_path = COALESCE(?, report_path) WHERE case_id = ?", args.verdict, args.report, args.case_id)
    log(cur, args.case_id, "Closed", f"{args.verdict}: {args.report or 'no report'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    p = sub.add_parser("open")
    p.add_argument("title")
    p.add_argument("--severity", required=True, choices=["Critical", "High", "Medium", "Low"])
    p.add_argument("--rules", required=True, help="comma-separated Wazuh rule IDs")
    p.add_argument("--assign")
    p = sub.add_parser("assign")
    p.add_argument("case_id", type=int)
    p.add_argument("who")
    p = sub.add_parser("note")
    p.add_argument("case_id", type=int)
    p.add_argument("text")
    p = sub.add_parser("close")
    p.add_argument("case_id", type=int)
    p.add_argument("--verdict", required=True, choices=["True positive", "Benign", "Low risk"])
    p.add_argument("--report")
    args = parser.parse_args()

    conn = pyodbc.connect(CONN_STR)
    cur = conn.cursor()
    {"list": cmd_list, "open": cmd_open, "assign": cmd_assign, "note": cmd_note, "close": cmd_close}[args.command](cur, args)
    conn.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
