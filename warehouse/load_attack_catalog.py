"""Load the Wazuh server's ATT&CK catalog and rule map into the warehouse.

Usage (from the repo root), after exporting on the Wazuh server with
wazuh/manager/export_attack_catalog.py:
    .venv\\Scripts\\python.exe warehouse\\load_attack_catalog.py warehouse\\data\\attack-catalog.json

Replaces sg.attack_catalog, sg.attack_catalog_tactics and sg.rule_attack_map
in one transaction, then records the load in sg.attack_catalog_loads.
Re-run after every Wazuh upgrade.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyodbc

CONN_STR = (
    "Driver={ODBC Driver 18 for SQL Server};Server=localhost;Database=SentinelGridWarehouse;"
    "Trusted_Connection=yes;TrustServerCertificate=yes"
)

# Rule files whose data source this lab actually sends to Wazuh (see
# wazuh/agent/default-agent.conf and the manager's own log collection). Listed
# by name on purpose: pattern matching wrongly caught "mailscanner" and
# "netscaler" as SCA and Windows server products (DHCP, FTP) as Windows logs.
# Every other rule file ships with Wazuh but has no data here (cloud services,
# network appliances, web and mail servers). Review this when a source is added.
COLLECTED_FILES = {
    "Windows event logs": {
        "0580-win-security_rules.xml", "0585-win-application_rules.xml", "0590-win-system_rules.xml",
        "0620-win-generic_rules.xml", "0840-win_event_channel.xml", "0220-msauth_rules.xml",
        "0565-ms_ipsec_rules.xml", "0440-ms_sqlserver_rules.xml", "0955-WEF-baseline_rules.xml",
    },
    "Windows Sysmon": {
        "0330-sysmon_rules.xml", "0595-win-sysmon_rules.xml", "0800-sysmon_id_1.xml", "0810-sysmon_id_3.xml",
        "0820-sysmon_id_7.xml", "0830-sysmon_id_11.xml", "0860-sysmon_id_13.xml", "0870-sysmon_id_8.xml",
        "0945-sysmon_id_10.xml", "0950-sysmon_id_20.xml",
    },
    "Windows PowerShell": {"0915-win-powershell_rules.xml"},
    "Windows Defender": {"0600-win-wdefender_rules.xml"},
    "Wazuh modules (FIM, SCA)": {"0015-ossec_rules.xml", "0017-wazuh-api_rules.xml"},
    "Linux host (Wazuh server)": {"0020-syslog_rules.xml", "0085-pam_rules.xml", "0095-sshd_rules.xml"},
}
FILE_FAMILY = {f: family for family, files in COLLECTED_FILES.items() for f in files}


def classify(rule: dict) -> tuple[str, bool]:
    if rule.get("local"):
        return "Watchtide custom rules", True
    family = FILE_FAMILY.get(rule["file"])
    return (family, True) if family else ("Not collected here", False)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    export = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    if export.get("errors"):
        raise SystemExit(f"export reported errors, fix the export first: {export['errors']}")
    catalog = export["catalog"]

    tactic_ext = {t["stix_id"]: t["tactic_id"] for t in catalog["tactics"] if t.get("tactic_id")}
    platforms = {}
    for p in catalog.get("platforms", []):
        platforms.setdefault(p["stix_id"], set()).add(p["platform"])
    stix_to_ext = {t["stix_id"]: t["technique_id"] for t in catalog["techniques"] if t.get("technique_id")}

    techniques = []
    for t in catalog["techniques"]:
        ext = t.get("technique_id")
        if not ext or not ext.startswith("T"):
            continue
        parent = stix_to_ext.get(t.get("subtechnique_of")) or (ext.split(".")[0] if "." in ext else None)
        active = not t.get("deprecated") and not t.get("revoked")
        techniques.append((ext, t["name"], parent, ",".join(sorted(platforms.get(t["stix_id"], []))) or None, active))
    technique_ids = {t[0] for t in techniques}

    pairs = set()
    for ph in catalog["phases"]:
        ext, tactic = stix_to_ext.get(ph["technique"]), tactic_ext.get(ph["tactic"])
        if ext and tactic:
            pairs.add((ext, tactic))

    rule_rows, families = [], {}
    for rule in export["rules"]:
        family, collected = classify(rule)
        families.setdefault((family, collected), set()).add(rule["file"])
        for technique_id in rule["techniques"]:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id):
                continue   # e.g. "$(threat.software.id)": filled in per event, not a fixed mapping
            rule_rows.append((rule["rule_id"], technique_id, min(rule["level"], 255), rule["description"][:512],
                              rule["file"][:128], family, collected))

    conn = pyodbc.connect(CONN_STR)
    cur = conn.cursor()
    cur.fast_executemany = True
    cur.execute("DELETE FROM sg.rule_attack_map")
    cur.execute("DELETE FROM sg.attack_catalog_tactics")
    cur.execute("DELETE FROM sg.attack_catalog")
    cur.executemany("INSERT INTO sg.attack_catalog (technique_id, technique_name, parent_technique_id, platforms, is_active)"
                    " VALUES (?, ?, ?, ?, ?)", techniques)
    cur.executemany("INSERT INTO sg.attack_catalog_tactics (technique_id, tactic_id) VALUES (?, ?)", sorted(pairs))
    cur.executemany("INSERT INTO sg.rule_attack_map (rule_id, technique_id, rule_level, description, rule_file,"
                    " source_family, collected_here) VALUES (?, ?, ?, ?, ?, ?, ?)", rule_rows)
    exported = export.get("exported_at_utc")
    cur.execute("INSERT INTO sg.attack_catalog_loads (loaded_at_utc, exported_at_utc, wazuh_version, attack_version,"
                " techniques, rules_with_attack) VALUES (?, ?, ?, ?, ?, ?)",
                datetime.now(timezone.utc).replace(tzinfo=None),
                datetime.strptime(exported, "%Y-%m-%dT%H:%M:%SZ") if exported else None,
                export.get("wazuh_version") or None,
                catalog.get("metadata", {}).get("mitre_version") or None,
                len(techniques), len(export["rules"]))
    conn.commit()

    unknown = sorted({rid for rid, tid, *_ in rule_rows if tid not in technique_ids})
    print(f"loaded {len(techniques)} techniques, {len(pairs)} technique-tactic pairs, "
          f"{len(export['rules'])} rules ({len(rule_rows)} rule-technique links)")
    for (family, collected), files in sorted(families.items()):
        print(f"  {'collected' if collected else 'not collected':13}  {family:28} {len(files):3} files")
    if unknown:
        print(f"warning: {len(unknown)} rules reference techniques missing from the catalog, e.g. {unknown[:5]}")

    # Self-check: a rule that has fired here must come from a source marked collected.
    misfiled = cur.execute("""SELECT DISTINCT m.rule_id, m.rule_file FROM sg.rule_attack_map AS m
                              WHERE m.collected_here = 0
                                AND EXISTS (SELECT 1 FROM sg.alerts AS a WHERE a.rule_id = m.rule_id)""").fetchall()
    if misfiled:
        print("error: rules that fired here are classified as not collected; add their files to COLLECTED_FILES:")
        for rule_id, rule_file in misfiled:
            print(f"  rule {rule_id} in {rule_file}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
