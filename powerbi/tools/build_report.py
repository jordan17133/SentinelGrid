"""Write the five report pages (PBIR) for the Watchtide Power BI project.

Usage (from the repo root, after build_model.py, with Power BI Desktop closed):
    .venv\\Scripts\\python.exe powerbi\\tools\\build_report.py

Idempotent: page and visual folders are named from stable hashes, and the
generated pages are rewritten in full on every run, so layout changes belong
here rather than in Power BI Desktop. Page 1 keeps its original page id.
Colors follow one rule throughout: gray is "before" (first scan), blue is now.
"""

import hashlib
import json
import shutil
from pathlib import Path

REPORT = Path(__file__).resolve().parents[1] / "SentinelGrid.Report" / "definition"
PAGES = REPORT / "pages"
SCHEMA = "https://developer.microsoft.com/json-schemas/fabric/item/report/definition"

# Palette (dataviz reference instance): emphasis = gray for "before", blue for "now".
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
BEFORE, NOW, NOW_LIGHT = "#c3c2b7", "#2a78d6", "#86b6ef"
FAINT, CRITICAL, ORANGE = "#e1e0d9", "#d03b3b", "#eb6834"
W, H, M, GAP = 1280, 720, 24, 12


def hid(*parts) -> str:
    return hashlib.sha1("/".join(parts).encode()).hexdigest()[:20]


def lit(v):
    return {"expr": {"Literal": {"Value": v}}}


def rawlit(v):
    """A literal inside a query expression (filters, selectors): no "expr" wrapper."""
    return {"Literal": {"Value": v}}


def b(v: bool):
    return lit("true" if v else "false")


def num(v):
    return lit(f"{v}D")


def txt(v: str):
    return lit("'" + v.replace("'", "''") + "'")


def color(hexv: str):
    return {"solid": {"color": lit(f"'{hexv}'")}}


def col(entity, prop):
    return {"Column": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def mea(entity, prop):
    return {"Measure": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def proj(field, display=None, active=None):
    kind = "Column" if "Column" in field else "Measure"
    entity = field[kind]["Expression"]["SourceRef"]["Entity"]
    prop = field[kind]["Property"]
    p = {"field": field, "queryRef": f"{entity}.{prop}", "nativeQueryRef": display or prop}
    if display:
        p["displayName"] = display
    if active is not None:
        p["active"] = active
    return p


def qref(field):
    kind = "Column" if "Column" in field else "Measure"
    return f"{field[kind]['Expression']['SourceRef']['Entity']}.{field[kind]['Property']}"


def sort(field, direction="Descending"):
    return {"sort": [{"field": field, "direction": direction}]}


def series_eq(field, value):
    """Selector for one value of a legend (series) column."""
    return {"data": [{"scopeId": {"Comparison": {"ComparisonKind": 0, "Left": field, "Right": rawlit(f"'{value}'")}}}]}


def frame(title=None, subtitle=None, border=True):
    """Container formatting shared by every chart: title, white card, hairline border."""
    o = {
        "title": [{"properties": {"show": b(bool(title)), **({"text": txt(title)} if title else {}),
                                  "fontColor": color(INK), "fontSize": num(11), "bold": b(True)}}],
        "background": [{"properties": {"show": b(border), "color": color("#ffffff"), "transparency": num(0)}}],
        "border": [{"properties": {"show": b(border), "color": color(FAINT), "radius": num(6), "width": num(1)}}],
        "dropShadow": [{"properties": {"show": b(False)}}],
        "padding": [{"properties": {k: num(10 if border else 0) for k in ("top", "bottom", "left", "right")}}],
    }
    o["subTitle"] = [{"properties": {"show": b(bool(subtitle)), **({"text": txt(subtitle)} if subtitle else {}),
                                     "fontColor": color(INK2), "fontSize": num(9)}}]
    return o


def container(page, key, x, y, w, h, visual, objs=None, filters=None, z=0):
    name = hid(page, key)
    v = {"$schema": f"{SCHEMA}/visualContainer/2.13.0/schema.json", "name": name,
         "position": {"x": round(x), "y": round(y), "z": z, "height": round(h), "width": round(w), "tabOrder": z},
         "visual": visual}
    if objs is not None:
        v["visual"]["visualContainerObjects"] = objs
    v["visual"]["drillFilterOtherVisuals"] = True
    if filters:
        v["filterConfig"] = {"filters": filters}
    return name, v


def textbox(runs_by_paragraph):
    paragraphs = []
    for runs in runs_by_paragraph:
        paragraphs.append({"textRuns": [{"value": t, "textStyle": style} for t, style in runs]})
    return {"visualType": "textbox", "objects": {"general": [{"properties": {"paragraphs": paragraphs}}]}}


def header(page, title, subtitle):
    return container(page, "header", M, 10, 960, 66, textbox([
        [(title, {"fontWeight": "bold", "fontSize": "20pt", "color": INK, "fontFamily": "Segoe UI Semibold"})],
        [(subtitle, {"fontSize": "10.5pt", "color": INK2})],
    ]), objs=frame(border=False))


def footer(page, text, y=H - 26, w=W - 2 * M, x=M, key="footer"):
    return container(page, key, x, y, w, 22, textbox([[(text, {"fontSize": "8pt", "color": MUTED})]]),
                     objs=frame(border=False))


def card(page, key, x, y, w, h, field, label, value_color=INK, font=24):
    visual = {
        "visualType": "cardVisual",
        "query": {"queryState": {"Data": {"projections": [proj(field, label)]}}},
        "objects": {
            "value": [{"properties": {"fontColor": color(value_color), "fontSize": num(font)}, "selector": {"id": "default"}}],
            "label": [{"properties": {"show": b(bool(label)), "fontColor": color(INK2), "fontSize": num(10)},
                       "selector": {"id": "default"}}],
        },
    }
    return container(page, key, x, y, w, h, visual, objs=frame(border=bool(label)))


def kpi_row(page, items, y=86, h=92):
    n = len(items)
    w = (W - 2 * M - (n - 1) * GAP) / n
    out = []
    for i, (field, label, *rest) in enumerate(items):
        out.append(card(page, f"kpi{i}", M + i * (w + GAP), y, w, h, field, label, *(rest or [])))
    return out


def axis_objects(value_axis=True, category_title=False, legend=None, labels=True, label_size=9):
    o = {
        "categoryAxis": [{"properties": {"showAxisTitle": b(category_title), "fontSize": num(9), "labelColor": color(INK2)}}],
        "valueAxis": [{"properties": {"show": b(value_axis), "showAxisTitle": b(False), "fontSize": num(9),
                                      "labelColor": color(MUTED), "gridlineShow": b(value_axis), "gridlineColor": color(FAINT)}}],
        "labels": [{"properties": {"show": b(labels), "fontSize": num(label_size), "color": color(INK2),
                                    "labelDisplayUnits": num(1)}}],
    }
    if legend is None:
        o["legend"] = [{"properties": {"show": b(False)}}]
    else:
        o["legend"] = [{"properties": {"show": b(True), "position": lit(f"'{legend}'"), "fontSize": num(9), "labelColor": color(INK2)}}]
    return o


def bar(page, key, x, y, w, h, kind, category, values, title, subtitle=None, series=None, colors=None,
        series_colors=None, legend="Top", value_axis=False, topn=None, sort_by=None, sort_dir="Descending",
        filters=None, extra=None, label_size=9):
    """kind: clusteredBarChart, barChart (stacked), clusteredColumnChart, columnChart (stacked)."""
    state = {"Category": {"projections": [proj(category, active=True)]},
             "Y": {"projections": [proj(f, d) for f, d in values]}}
    if series is not None:
        state["Series"] = {"projections": [proj(series)]}
    objects = axis_objects(value_axis=value_axis, legend=legend if (series is not None or len(values) > 1) else None,
                           label_size=label_size)
    points = []
    for f, c in (colors or []):
        points.append({"properties": {"fill": color(c)}, "selector": {"metadata": qref(f)}})
    if series is None and len(values) == 1 and colors:
        points.insert(0, {"properties": {"fill": color(colors[0][1])}})
    for value, c in (series_colors or []):
        points.append({"properties": {"fill": color(c)}, "selector": series_eq(series, value)})
    if points:
        objects["dataPoint"] = points
    if kind in ("barChart", "columnChart"):
        objects["totals"] = [{"properties": {"show": b(True), "fontSize": num(9), "color": color(INK2)}}]
    if extra:
        for k, v in extra.items():
            objects[k] = v
    visual = {"visualType": kind, "query": {"queryState": state}, "objects": objects}
    if sort_by is not None:
        visual["query"]["sortDefinition"] = sort(sort_by, sort_dir)
    all_filters = list(filters or [])
    if topn:
        n, by = topn
        all_filters.append(topn_filter(page, key, category, by, n))
    return container(page, key, x, y, w, h, visual, objs=frame(title, subtitle), filters=all_filters)


def topn_filter(page, key, field, by, n):
    entity = field["Column"]["Expression"]["SourceRef"]["Entity"]
    prop = field["Column"]["Property"]
    by_kind = "Measure" if "Measure" in by else "Column"
    return {"name": hid(page, key, "topn"), "field": field, "type": "TopN", "filter": {
        "Version": 2,
        "From": [{"Name": "subquery", "Expression": {"Subquery": {"Query": {
            "Version": 2, "From": [{"Name": "r", "Entity": entity, "Type": 0}],
            "Select": [{"Column": {"Expression": {"SourceRef": {"Source": "r"}}, "Property": prop}, "Name": "field"}],
            "OrderBy": [{"Direction": 2, "Expression": {by_kind: {"Expression": {"SourceRef": {"Source": "r"}},
                                                                  "Property": by[by_kind]["Property"]}}}],
            "Top": n}}}, "Type": 2},
            {"Name": "r", "Entity": entity, "Type": 0}],
        "Where": [{"Condition": {"In": {"Expressions": [{"Column": {"Expression": {"SourceRef": {"Source": "r"}}, "Property": prop}}],
                                        "Table": {"SourceRef": {"Source": "subquery"}}}}}]}}


def in_filter(page, key, field, values, hidden=False):
    entity = field["Column"]["Expression"]["SourceRef"]["Entity"]
    prop = field["Column"]["Property"]
    f = {"name": hid(page, key, "in", prop), "field": field, "type": "Categorical", "filter": {
        "Version": 2, "From": [{"Name": "r", "Entity": entity, "Type": 0}],
        "Where": [{"Condition": {"In": {"Expressions": [{"Column": {"Expression": {"SourceRef": {"Source": "r"}}, "Property": prop}}],
                                        "Values": [[rawlit(f"{v}L" if isinstance(v, int) else f"'{v}'")]
                                                   for v in values]}}}]}}
    if hidden:
        f["isHiddenInViewMode"] = True
    return f


def line(page, key, x, y, w, h, category, values, title, subtitle=None, colors=None, categorical=False,
         labels=True, value_axis=True):
    state = {"Category": {"projections": [proj(category, active=True)]},
             "Y": {"projections": [proj(f, d) for f, d in values]}}
    objects = axis_objects(value_axis=value_axis, legend="Top" if len(values) > 1 else None, labels=labels)
    if categorical:
        objects["categoryAxis"][0]["properties"]["axisType"] = lit("'Categorical'")
    objects["lineStyles"] = [{"properties": {"showMarker": b(True), "markerSize": num(4), "strokeWidth": num(2)}}]
    if colors:
        objects["dataPoint"] = [{"properties": {"fill": color(c)}, "selector": {"metadata": qref(f)}} for f, c in colors]
    visual = {"visualType": "lineChart", "query": {"queryState": state}, "objects": objects}
    return container(page, key, x, y, w, h, visual, objs=frame(title, subtitle))


def table(page, key, x, y, w, h, columns, title, subtitle=None, sort_by=None, sort_dir="Descending", widths=None,
          filters=None):
    visual = {
        "visualType": "tableEx",
        "query": {"queryState": {"Values": {"projections": [proj(f, d) for f, d in columns]}}},
        "objects": {
            "values": [{"properties": {"fontSize": num(9), "fontColorPrimary": color(INK), "backColorSecondary": color("#f9f9f7"),
                                       "wordWrap": b(True)}}],
            "columnHeaders": [{"properties": {"fontSize": num(9), "fontColor": color(INK2), "bold": b(True)}}],
            "grid": [{"properties": {"gridHorizontal": b(False), "rowPadding": num(3)}}],
            "total": [{"properties": {"totals": b(False)}}],
        },
    }
    if widths:
        visual["objects"]["columnWidth"] = [{"properties": {"value": num(wd)}, "selector": {"metadata": qref(f)}}
                                            for f, wd in widths]
    if sort_by is not None:
        visual["query"]["sortDefinition"] = sort(sort_by, sort_dir)
    return container(page, key, x, y, w, h, visual, objs=frame(title, subtitle), filters=filters)


def slicer(page, key, x, y, w, h, field, title, default=None):
    objects = {
        "data": [{"properties": {"mode": lit("'Dropdown'")}}],
        "selection": [{"properties": {"singleSelect": b(True), "strictSingleSelect": b(True)}}],
        "header": [{"properties": {"show": b(True), "text": txt(title), "fontColor": color(INK2), "textSize": num(9)}}],
        "items": [{"properties": {"textSize": num(10), "fontColor": color(INK)}}],
    }
    if default is not None:
        entity = field["Column"]["Expression"]["SourceRef"]["Entity"]
        prop = field["Column"]["Property"]
        objects["general"] = [{"properties": {"filter": {"filter": {
            "Version": 2, "From": [{"Name": "r", "Entity": entity, "Type": 0}],
            "Where": [{"Condition": {"In": {"Expressions": [{"Column": {"Expression": {"SourceRef": {"Source": "r"}}, "Property": prop}}],
                                            "Values": [[rawlit(f"'{default}'")]]}}}]}}}}]
    visual = {"visualType": "slicer", "query": {"queryState": {"Values": {"projections": [proj(field, active=True)]}}},
              "objects": objects}
    return container(page, key, x, y, w, h, visual, objs=frame(border=False))


# ---------------------------------------------------------------- pages

VF, CC, CS = "rpt vulnerability_findings", "rpt cis_check_results", "rpt cis_score_history"
AO, AC, AI = "rpt attack_observed", "rpt attack_coverage", "rpt attack_catalog_info"
PS, LR, LAT, AH = "rpt pipeline_status", "rpt load_runs", "rpt ingest_latency_hourly", "rpt agent_health"
ROW2_Y, ROW2_H = 190, 236
ROW3_Y, ROW3_H = ROW2_Y + ROW2_H + GAP, 246


def posture_page():
    p = "posture"
    v = [header(p, "Endpoint Posture",
                "Vulnerability findings and CIS benchmark results, rebuilt from Wazuh alerts. Gray is the first scan, blue is now."),
         slicer(p, "agent", W - M - 200, 18, 200, 56, col(AH, "agent_name"), "Endpoint", default="jordan-pc")]
    v += kpi_row(p, [
        (mea(VF, "All findings"), "Findings, all time"),
        (mea(VF, "Open now"), "Open now", NOW),
        (mea(VF, "Critical open"), "Critical open"),
        (mea(CS, "CIS score at baseline"), "CIS score, first scan", MUTED),
        (mea(CS, "CIS score now"), "CIS score now", NOW),
        (mea(CC, "Checks fixed"), "CIS checks fixed"),
    ])
    w3 = (W - 2 * M - 2 * GAP) / 3
    v.append(bar(p, "sev", M, ROW2_Y, w3, ROW2_H, "clusteredBarChart", col(VF, "severity"),
                 [(mea(VF, "All findings"), "All time"), (mea(VF, "Open now"), "Open now")],
                 "Vulnerabilities by severity", colors=[(mea(VF, "All findings"), BEFORE), (mea(VF, "Open now"), NOW)],
                 sort_by=col(VF, "severity"), sort_dir="Ascending"))
    v.append(bar(p, "pkg", M + w3 + GAP, ROW2_Y, w3, ROW2_H, "barChart", col(VF, "package_name"),
                 [(mea(VF, "All findings"), "Findings")], "Vulnerabilities by software package",
                 series=col(VF, "status"), series_colors=[("Resolved", BEFORE), ("Open", NOW)],
                 topn=(6, mea(VF, "All findings")), sort_by=mea(VF, "All findings")))
    v.append(line(p, "score", M + 2 * (w3 + GAP), ROW2_Y, w3, ROW2_H, col(CS, "scan_time_local"),
                  [(mea(CS, "CIS score"), "CIS score")], "CIS benchmark score after each scan",
                  colors=[(mea(CS, "CIS score"), NOW)], categorical=True, value_axis=False))
    wl = 520
    v.append(bar(p, "sections", M, ROW3_Y, wl, ROW3_H, "clusteredBarChart", col(CC, "section_label"),
                 [(mea(CC, "Passing at baseline"), "First scan"), (mea(CC, "Passing now"), "Now")],
                 "CIS checks passing, by benchmark section",
                 colors=[(mea(CC, "Passing at baseline"), BEFORE), (mea(CC, "Passing now"), NOW)],
                 sort_by=col(CC, "section_label"), sort_dir="Ascending", label_size=8))
    v.append(table(p, "fixed", M + wl + GAP, ROW3_Y, W - 2 * M - wl - GAP, ROW3_H,
                   [(col(CC, "cis_ref"), "CIS"), (col(CC, "title"), "Check fixed"), (col(CC, "section_label"), "Section"),
                    (col(CC, "last_change_local"), "Confirmed by Wazuh")],
                   "Checks fixed since the first scan", sort_by=col(CC, "cis_section"), sort_dir="Ascending",
                   widths=[(col(CC, "cis_ref"), 52), (col(CC, "title"), 330), (col(CC, "section_label"), 150)],
                   filters=[in_filter(p, "fixed", col(CC, "change_status"), ["Fixed"], hidden=True)]))
    v.append(footer(p, "Source: Wazuh vulnerability-detector and SCA alerts in SentinelGridWarehouse "
                       "(rpt.vulnerability_findings, rpt.cis_check_results, rpt.cis_score_history). "
                       "Every finding and check traces to a Wazuh document ID."))
    return p, "Endpoint Posture", v


def attack_page():
    p = "attack"
    v = [header(p, "MITRE ATT&CK Coverage",
                "What the deployed Wazuh rules can detect, and what fired here. Fired is not attacked: most of it is benign.")]
    v += kpi_row(p, [
        (mea(AO, "Techniques fired"), "Techniques fired here", NOW),
        (mea("rpt alert_tactics", "Tactics with activity"), "Tactics with activity (of 14)"),
        (mea(AC, "Techniques with a ready rule"), "Techniques with a ready rule"),
        (mea(AC, "Rule coverage"), "Rule coverage"),
        (mea("rpt alert_techniques", "Alerts mapped to ATT&CK"), "Alerts mapped to ATT&CK"),
    ])
    h = H - ROW2_Y - 34
    wl = 540
    v.append(bar(p, "tactics", M, ROW2_Y, wl, h, "barChart", col(AC, "tactic_name"),
                 [(mea(AC, "Techniques"), "Techniques")], "Coverage by tactic (Enterprise ATT&CK, Windows and Linux)",
                 series=col(AC, "coverage_status"),
                 series_colors=[("Fired here", NOW), ("Rule ready, not fired", NOW_LIGHT),
                                ("Rule exists, source not collected", BEFORE), ("No Wazuh rule", FAINT)],
                 sort_by=col(AC, "tactic_name"), sort_dir="Ascending", legend="Top"))
    v.append(table(p, "observed", M + wl + GAP, ROW2_Y, W - 2 * M - wl - GAP, h,
                   [(col(AO, "technique_label"), "Technique"), (col(AO, "tactic_names"), "Tactic"),
                    (col(AO, "alerts"), "Alerts"), (col(AO, "top_rule_description"), "Main rule"),
                    (col(AO, "top_rule_triage"), "Triage")],
                   "Techniques that fired here", sort_by=col(AO, "alerts"),
                   widths=[(col(AO, "technique_label"), 150), (col(AO, "tactic_names"), 110), (col(AO, "alerts"), 46),
                           (col(AO, "top_rule_description"), 175), (col(AO, "top_rule_triage"), 150)]))
    v.append(card(p, "catalog", M, H - 30, 420, 26, mea(AI, "Catalog source"), "", MUTED, 8))
    v.append(footer(p, "Coverage = a deployed rule is tagged with the technique and its data source is collected here. "
                       "Proof of detection needs attack simulations.",
                    x=M + 432, w=W - 2 * M - 432, key="footer"))
    return p, "ATT&CK Coverage", v


def pipeline_page():
    p = "pipeline"
    v = [header(p, "Pipeline Health",
                "Is data arriving, how late is it, does the loader fail, and is the warehouse within its limits?")]
    v += kpi_row(p, [
        (mea(PS, "Minutes since last load"), "Minutes since last load"),
        (mea(PS, "Loader success 7d"), "Loader success, 7 days", NOW),
        (mea(PS, "Median latency"), "Alert to SQL, median"),
        (mea(PS, "95th pct latency"), "Alert to SQL, p95"),
        (mea(PS, "Alerts loaded 24h"), "Alerts loaded, 24h"),
        (mea(PS, "Warehouse size"), "Warehouse size"),
    ])
    half = (W - 2 * M - GAP) / 2
    v.append(bar(p, "runs", M, ROW2_Y, half, ROW2_H, "columnChart", col(LR, "started_hour_local"),
                 [(mea(LR, "Runs"), "Runs")], "Loader runs per hour (scheduled every 15 minutes)",
                 series=col(LR, "status"), series_colors=[("succeeded", NOW), ("failed", CRITICAL)],
                 value_axis=True, extra={"labels": [{"properties": {"show": b(False)}}]}))
    v.append(line(p, "latency", M + half + GAP, ROW2_Y, half, ROW2_H, col(LAT, "loaded_hour_local"),
                  [(mea(LAT, "Median minutes"), "Median"), (mea(LAT, "95th percentile minutes"), "95th percentile")],
                  "Minutes from Wazuh alert to SQL row, by hour loaded",
                  colors=[(mea(LAT, "Median minutes"), NOW), (mea(LAT, "95th percentile minutes"), ORANGE)],
                  labels=False))
    v.append(table(p, "agents", M, ROW3_Y, half, ROW3_H,
                   [(col(AH, "agent_name"), "Endpoint"), (col(AH, "minutes_since_last_alert"), "Minutes since last alert"),
                    (col(AH, "alerts_last_24h"), "Alerts, 24 hours")],
                   "Endpoints reporting", sort_by=col(AH, "agent_name"), sort_dir="Ascending"))
    v.append(table(p, "failures", M + half + GAP, ROW3_Y, half, ROW3_H,
                   [(col(LR, "started_at_local"), "Started"), (col(LR, "error_message"), "Error")],
                   "Failed loader runs", sort_by=col(LR, "started_at_local"),
                   widths=[(col(LR, "started_at_local"), 130), (col(LR, "error_message"), 430)],
                   filters=[in_filter(p, "failures", col(LR, "status"), ["failed"], hidden=True)]))
    v.append(card(p, "asof", M, H - 30, 420, 26, mea(PS, "Data as of"), "", MUTED, 8))
    v.append(footer(p, "Source: sg.load_runs and sg.alerts.loaded_at_utc. Latency excludes the first run's backfill. "
                       "Warehouse data file is capped at 100 GB.",
                    x=M + 432, w=W - 2 * M - 432))
    return p, "Pipeline Health", v


AL = "rpt alerts"
SOC_PAGE_ID = "1bd820ead026a03a2405"   # page 1's original id, kept so existing links still work
# Severity uses the reserved status colors; every chart that shows it also labels it.
SEVERITY_COLORS = [("Critical", CRITICAL), ("High", "#ec835a"), ("Medium", "#fab219"), ("Low", BEFORE)]


def soc_page():
    p = "soc"
    v = [header(p, "SOC Overview",
                "Every alert Wazuh raised on this lab, loaded into SQL every 15 minutes. "
                "Tuned noise lands at Low, so Critical means investigate.")]
    v += kpi_row(p, [
        (mea(AL, "Total Alerts Display"), "Alerts, all time"),
        (mea(AL, "Alerts 24h Display"), "Alerts, last 24 hours"),
        (mea(AL, "Critical Alerts Display"), "Critical (level 15)", CRITICAL),
        (mea(AL, "High Alerts Display"), "High (level 12-14)"),
        (mea(AL, "Medium Alerts Display"), "Medium (level 7-11)"),
        (mea(AL, "Low Alerts Display"), "Low (level 0-6)", MUTED),
    ])
    wl = 760
    v.append(bar(p, "volume", M, ROW2_Y, wl, ROW2_H, "columnChart", col(AL, "alert_hour_start_local"),
                 [(mea(AL, "Total Alerts"), "Alerts")], "Alert volume by hour and severity",
                 series=col(AL, "severity_band"), series_colors=SEVERITY_COLORS, value_axis=True,
                 extra={"labels": [{"properties": {"show": b(False)}}],
                        "totals": [{"properties": {"show": b(False)}}]}))
    v.append(bar(p, "rules", M + wl + GAP, ROW2_Y, W - 2 * M - wl - GAP, ROW2_H, "clusteredBarChart",
                 col(AL, "rule_description"), [(mea(AL, "Total Alerts"), "Alerts")], "Busiest rules",
                 colors=[(mea(AL, "Total Alerts"), NOW)], topn=(6, mea(AL, "Total Alerts")),
                 sort_by=mea(AL, "Total Alerts"), label_size=8))
    wt = 700
    v.append(table(p, "critical", M, ROW3_Y, wt, ROW3_H,
                   [(col(AL, "alert_time_local"), "Time"), (col(AL, "severity_band"), "Severity"),
                    (col(AL, "rule_description"), "Rule"), (col(AL, "process_image"), "Process")],
                   "Critical and High alerts, newest first", sort_by=col(AL, "alert_time_local"),
                   widths=[(col(AL, "alert_time_local"), 120), (col(AL, "severity_band"), 58),
                           (col(AL, "rule_description"), 230), (col(AL, "process_image"), 250)],
                   filters=[in_filter(p, "critical", col(AL, "severity_band"), ["Critical", "High"], hidden=True)]))
    v.append(bar(p, "tuning", M + wt + GAP, ROW3_Y, W - 2 * M - wt - GAP, ROW3_H, "columnChart",
                 col(AL, "alert_hour_start_local"), [(mea(AL, "Total Alerts"), "Alerts")],
                 "Tuning in action: watchdog alerts moved from Critical to Low",
                 subtitle="Rule 92213 (Critical) and its tuned child 100100 (Low), live from Sep 30, 7:22 PM",
                 series=col(AL, "severity_band"), series_colors=SEVERITY_COLORS, value_axis=True,
                 extra={"labels": [{"properties": {"show": b(False)}}],
                        "totals": [{"properties": {"show": b(False)}}]},
                 filters=[in_filter(p, "tuning", col(AL, "rule_id"), [92213, 100100], hidden=True)]))
    v.append(footer(p, "Source: rpt.alerts in SentinelGridWarehouse, one row per Wazuh alert keyed by its Indexer "
                       "document ID. Severity bands follow the Wazuh dashboard. Tuning: triage/ and "
                       "wazuh/rules/sentinelgrid_tuning.xml."))
    return p, "SOC Overview", v


CASES = "rpt cases"


def cases_page():
    p = "cases"
    v = [header(p, "Cases",
                "Every investigation as a case: who owns it, what it found, and how long from first alert to verdict.")]
    v += kpi_row(p, [
        (mea(CASES, "Cases"), "Cases"),
        (mea(CASES, "Open cases"), "Open or in progress", ORANGE),
        (mea(CASES, "Closed cases"), "Closed"),
        (mea(CASES, "True positives"), "True positives", NOW),
        (mea(CASES, "Median hours to verdict"), "Median time to verdict"),
    ])
    half = (W - 2 * M - GAP) / 2
    v.append(bar(p, "ttv", M, ROW2_Y, half, ROW2_H, "clusteredBarChart", col(CASES, "case_number"),
                 [(mea(CASES, "Hours to verdict"), "Hours")], "Hours from first alert to verdict, by case",
                 sort_by=col(CASES, "case_number"), sort_dir="Ascending", legend=None))
    v.append(bar(p, "verdicts", M + half + GAP, ROW2_Y, half, ROW2_H, "clusteredBarChart", col(CASES, "verdict"),
                 [(mea(CASES, "Cases"), "Cases")], "Cases by verdict", legend=None,
                 series=col(CASES, "verdict"),
                 series_colors=[("True positive", CRITICAL), ("Benign", BEFORE), ("Low risk", ORANGE), ("Pending", ORANGE)]))
    v.append(table(p, "list", M, ROW3_Y, W - 2 * M, ROW3_H,
                   [(col(CASES, "case_number"), "Case"), (col(CASES, "title"), "Title"), (col(CASES, "severity"), "Severity"),
                    (col(CASES, "status"), "Status"), (col(CASES, "verdict"), "Verdict"),
                    (col(CASES, "first_alert_local"), "First alert"), (col(CASES, "hours_to_verdict"), "Hours to verdict"),
                    (col(CASES, "alerts_in_case"), "Alerts"), (col(CASES, "report_path"), "Report")],
                   "Case list", sort_by=col(CASES, "case_number"), sort_dir="Ascending",
                   widths=[(col(CASES, "case_number"), 60), (col(CASES, "title"), 290), (col(CASES, "report_path"), 330)]))
    v.append(footer(p, "Source: sg.cases, sg.case_rules and sg.case_events, managed with warehouse/cases.py. "
                       "Time to verdict runs from the first alert to closing; the first cases had no separate open time."))
    return p, "Cases", v


def main():
    pages_meta = json.loads((PAGES / "pages.json").read_text(encoding="utf-8"))
    order = []
    for key, display, visuals in (soc_page(), posture_page(), attack_page(), cases_page(), pipeline_page()):
        page_id = SOC_PAGE_ID if key == "soc" else hid("page", key)
        folder = PAGES / page_id
        if folder.exists():
            shutil.rmtree(folder)
        (folder / "visuals").mkdir(parents=True)
        page = {"$schema": f"{SCHEMA}/page/2.1.0/schema.json", "name": page_id, "displayName": display,
                "displayOption": "FitToPage", "height": H, "width": W,
                "objects": {"background": [{"properties": {"color": color("#f9f9f7"), "transparency": num(0)}}]}}
        (folder / "page.json").write_text(json.dumps(page, indent=2), encoding="utf-8", newline="\r\n")
        for z, (name, visual) in enumerate(visuals):
            visual["position"]["z"] = z * 1000
            visual["position"]["tabOrder"] = z * 1000
            (folder / "visuals" / name).mkdir()
            (folder / "visuals" / name / "visual.json").write_text(json.dumps(visual, indent=2), encoding="utf-8",
                                                                    newline="\r\n")
        order.append(page_id)
        print(f"{display}: {len(visuals)} visuals -> {page_id}")
    pages_meta["pageOrder"] = order
    pages_meta["activePageName"] = SOC_PAGE_ID   # open on the overview
    (PAGES / "pages.json").write_text(json.dumps(pages_meta, indent=2), encoding="utf-8", newline="\r\n")


if __name__ == "__main__":
    main()
