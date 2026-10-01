"""Add the posture, ATT&CK and pipeline tables to the SentinelGrid semantic model (TMDL).

Usage (from the repo root, with Power BI Desktop closed):
    .venv\\Scripts\\python.exe powerbi\\tools\\build_model.py

Idempotent: removes Power BI's auto date/time tables, (re)writes the generated
tables from the live SQL column types, appends new columns and measures to
existing tables, and rewrites relationships. Lineage tags are uuid5 of the
object path, so a re-run produces identical files.

Generated tables are rewritten in full: change them here, not in Power BI
Desktop, or the next run undoes the Desktop edit. Page 1's tables are only added to.
"""

import re
import uuid
from pathlib import Path

import pyodbc

ROOT = Path(__file__).resolve().parents[1] / "SentinelGrid.SemanticModel"
DEF = ROOT / "definition"
TABLES = DEF / "tables"
NS = uuid.UUID("5e1e5a1d-0000-4000-8000-53454e54494e")
CONN = ("Driver={ODBC Driver 18 for SQL Server};Server=localhost;Database=SentinelGridWarehouse;"
        "Trusted_Connection=yes;TrustServerCertificate=yes")


def tag(*parts) -> str:
    return str(uuid.uuid5(NS, "/".join(parts)))


SQL_TYPES = {
    "varchar": "string", "nvarchar": "string", "char": "string", "nchar": "string",
    "int": "int64", "bigint": "int64", "smallint": "int64", "tinyint": "int64", "bit": "boolean",
    "decimal": "double", "numeric": "double", "float": "double", "real": "double",
    "datetime2": "dateTime", "datetime": "dateTime", "date": "dateTime",
}

# Per table: measures (name, DAX, formatString or None), column overrides.
# Column override keys: format, sortBy, summarize, hidden.
SPEC = {
    "vulnerability_findings": {
        "measures": [
            ("All findings", "COUNTROWS('rpt vulnerability_findings') + 0", "#,0"),
            ("Open now", "CALCULATE([All findings], 'rpt vulnerability_findings'[status] = \"Open\")", "#,0"),
            ("Resolved", "CALCULATE([All findings], 'rpt vulnerability_findings'[status] = \"Resolved\")", "#,0"),
            ("Critical open", "CALCULATE([Open now], 'rpt vulnerability_findings'[severity] = \"Critical\")", "#,0"),
            ("Critical all time", "CALCULATE([All findings], 'rpt vulnerability_findings'[severity] = \"Critical\")", "#,0"),
            ("Findings reduced", "DIVIDE([Resolved], [All findings])", "0.0%"),
        ],
        "columns": {
            "severity": {"sortBy": "severity_sort"},
            "severity_sort": {"hidden": True},
            "base_score": {"format": "0.0", "summarize": "none"},
            "resolved_at_local": {"format": "General Date"},
        },
    },
    "cis_check_results": {
        "measures": [
            ("Checks", "COUNTROWS('rpt cis_check_results') + 0", "#,0"),
            ("Checks fixed", "CALCULATE([Checks], 'rpt cis_check_results'[change_status] = \"Fixed\")", "#,0"),
            ("Checks regressed", "CALCULATE([Checks], 'rpt cis_check_results'[change_status] = \"Regressed\")", "#,0"),
            ("Passing at baseline",
             "DIVIDE(CALCULATE([Checks], 'rpt cis_check_results'[baseline_result] = \"passed\"),\n"
             "CALCULATE([Checks], 'rpt cis_check_results'[baseline_result] IN {\"passed\", \"failed\"}))", "0%"),
            ("Passing now",
             "DIVIDE(CALCULATE([Checks], 'rpt cis_check_results'[current_result] = \"passed\"),\n"
             "CALCULATE([Checks], 'rpt cis_check_results'[current_result] IN {\"passed\", \"failed\"}))", "0%"),
        ],
        "columns": {
            "section_label": {"sortBy": "cis_section"},
            "cis_section": {"summarize": "none"},
            "check_id": {"summarize": "none"},
            "last_change_local": {"format": "mmm d, h:nn AM/PM"},
        },
    },
    "cis_score_history": {
        "measures": [
            ("CIS score", "DIVIDE(AVERAGE('rpt cis_score_history'[score_pct]), 100)", "0.0%"),
            ("CIS score now",
             "VAR latestScan = TOPN(1, 'rpt cis_score_history', 'rpt cis_score_history'[scan_time_local], DESC)\n"
             "RETURN DIVIDE(MAXX(latestScan, 'rpt cis_score_history'[score_pct]), 100)", "0.0%"),
            ("CIS score at baseline",
             "VAR firstScan = TOPN(1, 'rpt cis_score_history', 'rpt cis_score_history'[scan_time_local], ASC)\n"
             "RETURN DIVIDE(MAXX(firstScan, 'rpt cis_score_history'[score_pct]), 100)", "0.0%"),
        ],
        "columns": {
            "scan_time_local": {"format": "mmm d, h:nn AM/PM"},
            "score_pct": {"format": "0.0", "summarize": "none"},
            "scan_number": {"summarize": "none"},
        },
    },
    "attack_observed": {
        "measures": [
            ("Techniques fired", "COUNTROWS('rpt attack_observed') + 0", "#,0"),
            ("Technique alerts", "SUM('rpt attack_observed'[alerts]) + 0", "#,0"),
        ],
        "columns": {
            "top_rule_id": {"summarize": "none"},
            "max_level": {"summarize": "none"},
            "first_tactic_order": {"summarize": "none", "hidden": True},
            "top_rule_share_pct": {"format": "0.0", "summarize": "none"},
            "first_seen_local": {"format": "General Date"},
            "last_seen_local": {"format": "General Date"},
        },
    },
    "attack_coverage": {
        "measures": [
            ("Techniques", "DISTINCTCOUNT('rpt attack_coverage'[technique_id]) + 0", "#,0"),
            ("Techniques with a ready rule",
             "CALCULATE([Techniques], 'rpt attack_coverage'[coverage_sort] <= 2)", "#,0"),
            ("Rule coverage", "DIVIDE([Techniques with a ready rule], [Techniques])", "0%"),
        ],
        "columns": {
            "coverage_status": {"sortBy": "coverage_sort"},
            "coverage_sort": {"hidden": True, "summarize": "none"},
            "tactic_name": {"sortBy": "matrix_order"},
            "matrix_order": {"hidden": True, "summarize": "none"},
            "is_subtechnique": {"summarize": "none"},
            "last_seen_local": {"format": "General Date"},
        },
    },
    "attack_catalog_info": {
        "measures": [
            ("Catalog source",
             "VAR v = MAX('rpt attack_catalog_info'[wazuh_version])\n"
             "VAR d = MAX('rpt attack_catalog_info'[exported_at_utc])\n"
             "RETURN IF(ISBLANK(d), \"ATT&CK catalog not loaded yet\",\n"
             "    \"ATT&CK catalog and rule map exported from Wazuh \" & v & \" on \" & FORMAT(d, \"yyyy-mm-dd\"))", None),
        ],
        "columns": {"exported_at_utc": {"format": "General Date"}, "loaded_at_local": {"format": "General Date"}},
    },
    "pipeline_status": {
        "measures": [
            ("Minutes since last load", "MAX('rpt pipeline_status'[minutes_since_success])", "#,0"),
            ("Loader success 7d", "DIVIDE(MAX('rpt pipeline_status'[success_rate_7d_pct]), 100)", "0.0%"),
            ("Median latency", "MAX('rpt pipeline_status'[latency_p50_minutes_7d])", "0.0 \"min\""),
            ("95th pct latency", "MAX('rpt pipeline_status'[latency_p95_minutes_7d])", "0.0 \"min\""),
            # Text, because the new card visual always abbreviates numbers (7K) and has no display-units option.
            ("Alerts loaded 24h", "FORMAT(MAX('rpt pipeline_status'[alerts_loaded_24h]), \"#,0\")", None),
            ("Data as of",
             "\"Data as of \" & FORMAT(MAX('rpt pipeline_status'[as_of_local]), \"yyyy-mm-dd h:nn AM/PM\") & \" (US Eastern)\"", None),
            ("Warehouse size", "MAX('rpt pipeline_status'[data_used_mb])", "#,0 \"MB\""),
        ],
        "columns": {k: {"format": "General Date"} for k in ("as_of_local", "last_success_local", "newest_alert_local")},
    },
    "cases": {
        "measures": [
            ("Cases", "COUNTROWS('rpt cases') + 0", "#,0"),
            ("Open cases", "CALCULATE([Cases], 'rpt cases'[status] <> \"Closed\")", "#,0"),
            ("Closed cases", "CALCULATE([Cases], 'rpt cases'[status] = \"Closed\")", "#,0"),
            ("True positives", "CALCULATE([Cases], 'rpt cases'[verdict] = \"True positive\")", "#,0"),
            ("Median hours to verdict", "MEDIAN('rpt cases'[hours_to_verdict])", "0.0 \"h\""),
            ("Hours to verdict", "SUM('rpt cases'[hours_to_verdict])", "0.0"),
        ],
        "columns": {
            "severity": {"sortBy": "severity_order"},
            "severity_order": {"hidden": True},
            "case_id": {"summarize": "none"},
            "first_alert_local": {"format": "mmm d, h:nn AM/PM"},
            "closed_local": {"format": "mmm d, h:nn AM/PM"},
            **{k: {"format": "0.0", "summarize": "none"} for k in ("hours_to_verdict", "open_age_hours")},
            "alerts_in_case": {"format": "#,0", "summarize": "none"},
        },
    },
    "ingest_latency_hourly": {
        "measures": [
            ("Median minutes", "AVERAGE('rpt ingest_latency_hourly'[p50_minutes])", "0.0"),
            ("95th percentile minutes", "AVERAGE('rpt ingest_latency_hourly'[p95_minutes])", "0.0"),
        ],
        "columns": {"loaded_hour_local": {"format": "General Date"},
                    **{k: {"format": "0.0", "summarize": "none"} for k in ("p50_minutes", "p95_minutes", "max_minutes")}},
    },
}

# Columns appended to the existing rpt load_runs table, plus its measures.
LOAD_RUNS_NEW = [("started_at_local", "dateTime"), ("started_hour_local", "dateTime"), ("succeeded", "int64")]
LOAD_RUNS_MEASURES = [
    ("Runs", "COUNTROWS('rpt load_runs')", "#,0"),
    ("Succeeded runs", "CALCULATE([Runs], 'rpt load_runs'[status] = \"succeeded\")", "#,0"),
    ("Failed runs", "CALCULATE([Runs], 'rpt load_runs'[status] = \"failed\")", "#,0"),
]
# Measures appended to other existing tables.
EXTRA_MEASURES = {
    # Page 1 cards: text, because the new card visual abbreviates numbers (7K).
    "rpt alerts": [
        ("Total Alerts Display", "FORMAT([Total Alerts], \"#,0\")", None),
        ("Critical Alerts Display", "FORMAT([Critical Alerts] + 0, \"#,0\")", None),
        ("High Alerts Display", "FORMAT([High Alerts] + 0, \"#,0\")", None),
        ("Medium Alerts Display", "FORMAT([Medium Alerts] + 0, \"#,0\")", None),
        ("Alerts 24h Display",
         "FORMAT(CALCULATE([Total Alerts] + 0, 'rpt alerts'[alert_time_local] >= NOW() - 1), \"#,0\")", None),
    ],
    "rpt alert_tactics": [
        ("Tactics with activity", "DISTINCTCOUNT('rpt alert_tactics'[tactic]) + 0", "#,0"),
    ],
    "rpt alert_techniques": [
        ("Alerts mapped to ATT&CK",
         "DIVIDE(DISTINCTCOUNT('rpt alert_techniques'[doc_id]), COUNTROWS('rpt alerts'))", "0%"),
    ],
}

# Agent dimension: rpt agent_health filters the posture tables.
RELATIONSHIPS = [
    ("rpt vulnerability_findings", "agent_name", "rpt agent_health", "agent_name"),
    ("rpt cis_check_results", "agent_name", "rpt agent_health", "agent_name"),
    ("rpt cis_score_history", "agent_name", "rpt agent_health", "agent_name"),
    ("rpt alert_techniques", "doc_id", "rpt alerts", "doc_id"),
    ("rpt alert_tactics", "doc_id", "rpt alerts", "doc_id"),
]


def measure_block(table: str, name: str, dax: str, fmt) -> str:
    q = f"'{name}'" if re.search(r"[^A-Za-z0-9_]", name) else name
    lines = dax.split("\n")
    if len(lines) == 1:
        out = f"\tmeasure {q} = {dax}\n"
    else:
        out = f"\tmeasure {q} =\n" + "".join(f"\t\t\t{line}\n" for line in lines)
    if fmt:
        out += f"\t\tformatString: {fmt}\n"
    out += f"\t\tlineageTag: {tag(table, 'measure', name)}\n\n"
    return out


def column_block(table: str, name: str, dtype: str, sql_type: str, opts: dict) -> str:
    out = f"\tcolumn {name}\n\t\tdataType: {dtype}\n"
    if opts.get("hidden"):
        out += "\t\tisHidden\n"
    fmt = opts.get("format")
    if not fmt and dtype == "dateTime":
        fmt = "Long Date" if sql_type == "date" else "General Date"
    if not fmt and dtype == "int64":
        fmt = "0"
    if fmt:
        out += f"\t\tformatString: {fmt}\n"
    out += f"\t\tlineageTag: {tag(table, 'column', name)}\n"
    summarize = opts.get("summarize") or ("sum" if dtype in ("int64", "double") else "none")
    out += f"\t\tsummarizeBy: {summarize}\n\t\tsourceColumn: {name}\n"
    if opts.get("sortBy"):
        out += f"\t\tsortByColumn: {opts['sortBy']}\n"
    out += "\n\t\tannotation SummarizationSetBy = Automatic\n\n"
    return out


def partition_block(view: str) -> str:
    table = f"rpt {view}"
    return (f"\tpartition '{table}' = m\n\t\tmode: import\n\t\tsource =\n"
            f"\t\t\t\tlet\n"
            f"\t\t\t\t    Source = Sql.Database(\"localhost\", \"SentinelGridWarehouse\"),\n"
            f"\t\t\t\t    rpt_{view} = Source{{[Schema=\"rpt\",Item=\"{view}\"]}}[Data]\n"
            f"\t\t\t\tin\n"
            f"\t\t\t\t    rpt_{view}\n\n"
            f"\tannotation PBI_ResultType = Table\n")


def add_measures(table: str, text: str, measures: list) -> str:
    """Insert measures after the table's lineage tag, skipping ones already present."""
    for name, dax, fmt in measures:
        if f"measure '{name}'" not in text and f"measure {name} " not in text:
            head, rest = text.split("\n\n", 1)
            text = head + "\n\n" + measure_block(table, name, dax, fmt) + rest
    return text


def remove_auto_dates() -> None:
    for f in list(TABLES.glob("LocalDateTable_*.tmdl")) + list(TABLES.glob("DateTableTemplate_*.tmdl")):
        f.unlink()
    for f in TABLES.glob("*.tmdl"):
        text = f.read_text(encoding="utf-8")
        new = re.sub(r"\t\tvariation Variation\n(\t\t\t[^\n]*\n)+\n", "", text)
        if new != text:
            f.write_text(new, encoding="utf-8", newline="\r\n")


def main() -> None:
    remove_auto_dates()
    cur = pyodbc.connect(CONN).cursor()
    cols = {}
    for t, c, d in cur.execute("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
                               "WHERE TABLE_SCHEMA = 'rpt' ORDER BY TABLE_NAME, ORDINAL_POSITION"):
        cols.setdefault(t, []).append((c, d))

    for view, spec in SPEC.items():
        table = f"rpt {view}"
        out = f"table '{table}'\n\tlineageTag: {tag(table)}\n\n"
        for name, dax, fmt in spec["measures"]:
            out += measure_block(table, name, dax, fmt)
        for name, sql_type in cols[view]:
            out += column_block(table, name, SQL_TYPES[sql_type], sql_type, spec["columns"].get(name, {}))
        out += partition_block(view) + "\n"
        (TABLES / f"{table}.tmdl").write_text(out, encoding="utf-8", newline="\r\n")

    # rpt load_runs: append new columns before the partition, measures after the lineage tag.
    lr = TABLES / "rpt load_runs.tmdl"
    text = lr.read_text(encoding="utf-8")
    sql_types = dict(cols["load_runs"])
    for name, dtype in LOAD_RUNS_NEW:
        if f"\tcolumn {name}\n" not in text:
            opts = {"summarize": "none", "format": "mmm d, h:nn AM/PM"} if name == "started_at_local" else (
                {"summarize": "none"} if name != "succeeded" else {})
            block = column_block("rpt load_runs", name, dtype, sql_types[name], opts)
            text = text.replace("\tpartition 'rpt load_runs'", block + "\tpartition 'rpt load_runs'")
    lr.write_text(add_measures("rpt load_runs", text, LOAD_RUNS_MEASURES), encoding="utf-8", newline="\r\n")
    for table, measures in EXTRA_MEASURES.items():
        f = TABLES / f"{table}.tmdl"
        f.write_text(add_measures(table, f.read_text(encoding="utf-8"), measures), encoding="utf-8", newline="\r\n")

    rel = ""
    for f_table, f_col, t_table, t_col in RELATIONSHIPS:
        rel += (f"relationship {tag('rel', f_table, f_col, t_table, t_col)}\n"
                f"\tfromColumn: '{f_table}'.{f_col}\n\ttoColumn: '{t_table}'.{t_col}\n\n")
    (DEF / "relationships.tmdl").write_text(rel, encoding="utf-8", newline="\r\n")

    model = (DEF / "model.tmdl").read_text(encoding="utf-8")
    existing = [t.strip("'") for t in re.findall(r"^ref table (.+)$", model, re.M)]
    on_disk = {p.stem for p in TABLES.glob("*.tmdl")}
    tables = [t for t in existing if t in on_disk] + sorted(on_disk - set(existing))
    model = model.replace("annotation __PBI_TimeIntelligenceEnabled = 1", "annotation __PBI_TimeIntelligenceEnabled = 0")
    model = re.sub(r"(ref table [^\n]+\n)+", "".join(
        f"ref table '{t}'\n" if " " in t else f"ref table {t}\n" for t in tables), model, count=1)
    model = re.sub(r"annotation PBI_QueryOrder = \[[^\n]*\]",
                   "annotation PBI_QueryOrder = [" + ",".join(f'"{t}"' for t in sorted(tables)) + "]", model)
    (DEF / "model.tmdl").write_text(model, encoding="utf-8", newline="\r\n")
    print("tables:", ", ".join(tables))


if __name__ == "__main__":
    main()
