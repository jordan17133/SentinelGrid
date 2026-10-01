#!/usr/bin/env python3
"""Export what the Wazuh server knows about MITRE ATT&CK, for the coverage map.

Two things live only on the Wazuh server, not in the alerts:
  1. The ATT&CK catalog Wazuh ships (/var/ossec/var/db/mitre.db): every
     technique, its tactics and platforms.
  2. Which deployed rules map to which techniques (<mitre><id> in every rule
     file, minus files excluded in ossec.conf, with local overrides applied).

Together with the alerts already in the warehouse, that separates "a rule
exists for this technique" from "this technique actually fired here".

Read-only: opens mitre.db read-only and only reads rule files. Needs root
because both are readable only by root and the wazuh group.

    sudo python3 export_attack_catalog.py > attack-catalog.json

Then copy the JSON to Windows and load it with warehouse/load_attack_catalog.py.
Re-run after every Wazuh upgrade, since the ruleset and catalog change with it.
"""

import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

OSSEC = Path("/var/ossec")
RULE_DIRS = [OSSEC / "ruleset" / "rules", OSSEC / "etc" / "rules"]   # later wins on overwrite
OSSEC_CONF = OSSEC / "etc" / "ossec.conf"
MITRE_DB = OSSEC / "var" / "db" / "mitre.db"

COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
GROUP_RE = re.compile(r"<group\s+name\s*=\s*\"([^\"]*)\"")
RULE_RE = re.compile(r"<rule\b([^>]*)>(.*?)</rule>", re.S)
ATTR_RE = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")
DESC_RE = re.compile(r"<description>(.*?)</description>", re.S)
MITRE_RE = re.compile(r"<mitre>(.*?)</mitre>", re.S)
ID_RE = re.compile(r"<id>\s*([^<\s]+)\s*</id>")
EXCLUDE_RE = re.compile(r"<rule_exclude>\s*([^<\s]+)\s*</rule_exclude>")


def wazuh_version() -> str:
    try:
        out = subprocess.run([str(OSSEC / "bin" / "wazuh-control"), "info", "-v"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip()
    except OSError:
        return ""


def export_rules() -> list:
    """One entry per deployed rule that carries at least one ATT&CK technique.
    Uses regular expressions rather than an XML parser because Wazuh rule
    files are not single-root XML and some regexes contain bare '<'."""
    excluded = set(EXCLUDE_RE.findall(OSSEC_CONF.read_text(errors="replace")))
    rules = {}
    for rule_dir in RULE_DIRS:
        for path in sorted(rule_dir.glob("*.xml")):
            if path.name in excluded:
                continue
            text = COMMENT_RE.sub("", path.read_text(errors="replace"))
            groups = [(m.start(), m.group(1)) for m in GROUP_RE.finditer(text)]
            for m in RULE_RE.finditer(text):
                attrs = dict(ATTR_RE.findall(m.group(1)))
                if "id" not in attrs:
                    continue
                rule_id = int(attrs["id"])
                body = m.group(2)
                techniques = []
                for block in MITRE_RE.findall(body):
                    techniques += ID_RE.findall(block)
                desc = DESC_RE.search(body)
                group = next((g for pos, g in reversed(groups) if pos < m.start()), "")
                rules[rule_id] = {
                    "rule_id": rule_id,
                    "level": int(attrs.get("level", 0)),
                    "description": desc.group(1).strip() if desc else "",
                    "file": path.name,
                    "local": rule_dir == RULE_DIRS[1],
                    "groups": group,
                    "techniques": sorted(set(techniques)),
                }
    return [r for r in rules.values() if r["techniques"]]


def table_columns(con, table: str) -> list:
    return [row[1] for row in con.execute(f"PRAGMA table_info({table})")]


def export_catalog() -> dict:
    con = sqlite3.connect(f"file:{MITRE_DB}?mode=ro", uri=True)
    try:
        ext = {row[0]: row[1] for row in con.execute(
            "SELECT id, external_id FROM reference WHERE source = 'mitre-attack' AND external_id IS NOT NULL")}
        tactics = [
            {"stix_id": r[0], "tactic_id": ext.get(r[0]), "name": r[1], "short_name": r[2]}
            for r in con.execute("SELECT id, name, short_name FROM tactic")
        ]
        techniques = [
            {"stix_id": r[0], "technique_id": ext.get(r[0]), "name": r[1],
             "deprecated": bool(r[2]), "revoked": bool(r[3]), "subtechnique_of": r[4]}
            for r in con.execute("SELECT id, name, deprecated, revoked_by, subtechnique_of FROM technique")
        ]
        phases = [{"technique": r[0], "tactic": r[1]} for r in con.execute("SELECT tech_id, tactic_id FROM phase")]
        platforms = []
        if "platform" in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]:
            cols = table_columns(con, "platform")
            if len(cols) >= 2:
                platforms = [{"stix_id": r[0], "platform": r[1]}
                             for r in con.execute(f"SELECT {cols[0]}, {cols[1]} FROM platform")]
        metadata = {}
        if "metadata" in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]:
            metadata = {str(r[0]): str(r[1]) for r in con.execute("SELECT * FROM metadata")}
        return {"tactics": tactics, "techniques": techniques, "phases": phases,
                "platforms": platforms, "metadata": metadata}
    finally:
        con.close()


def schema_dump() -> list:
    """If the catalog query fails, ship the schema so the loader can be adapted."""
    try:
        con = sqlite3.connect(f"file:{MITRE_DB}?mode=ro", uri=True)
        return [r[0] for r in con.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")]
    except sqlite3.Error as exc:
        return [f"{type(exc).__name__}: {exc}"]


def main() -> int:
    result = {
        "exported_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "wazuh_version": wazuh_version(),
        "errors": [],
    }
    try:
        result["rules"] = export_rules()
    except OSError as exc:
        result["rules"] = []
        result["errors"].append(f"rules: {type(exc).__name__}: {exc}")
    try:
        result["catalog"] = export_catalog()
    except sqlite3.Error as exc:
        result["catalog"] = None
        result["errors"].append(f"catalog: {type(exc).__name__}: {exc}")
        result["mitre_db_schema"] = schema_dump()

    json.dump(result, sys.stdout)
    print(f"rules with ATT&CK mappings: {len(result['rules'])}; "
          f"techniques: {len((result.get('catalog') or {}).get('techniques', []))}; "
          f"errors: {len(result['errors'])}", file=sys.stderr)
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
