"""Builds reports/DATASET_REPORT.md from the live database so the numbers always match the data.
Run:  python reports/generate_dataset_report.py   (after python backend/app.py has built the DB once)"""
import os, sys, sqlite3
from collections import Counter
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
import app as A

if not os.path.exists(A.DB_PATH):
    A.init_db()
con = sqlite3.connect(A.DB_PATH); con.row_factory = sqlite3.Row
q = lambda s: [dict(r) for r in con.execute(s)]
tbl = lambda head, rows: "| " + " | ".join(head) + " |\n|" + "---|" * len(head) + "\n" + "\n".join("| " + " | ".join(str(c) for c in r) + " |" for r in rows) + "\n"
total = q("SELECT COUNT(*) n FROM threats")[0]["n"]
pct = lambda n: f"{100 * n / max(total, 1):.1f}%"
out = ["# Dataset Report\n", "_Generated automatically from the database. All data is **synthetic / demo only**._\n"]
out += ["## 1. Overview\n", tbl(["Metric", "Value"], [
    ["Threat records", total], ["Unique indicators", q("SELECT COUNT(DISTINCT indicator_value) n FROM threats")[0]["n"]],
    ["Campaign clusters", q("SELECT COUNT(DISTINCT campaign_id) n FROM threats")[0]["n"]], ["Total observations", q("SELECT SUM(observation_count) n FROM threats")[0]["n"]],
    ["Alerts after correlation", q("SELECT COUNT(*) n FROM alerts")[0]["n"]], ["Synthetic CVEs", q("SELECT COUNT(*) n FROM vulnerabilities")[0]["n"]],
    ["Average risk score", q("SELECT ROUND(AVG(risk_score),1) n FROM threats")[0]["n"]], ["Average confidence", q("SELECT ROUND(AVG(confidence_score),1) n FROM threats")[0]["n"]]])]
for title, col, order in [("2. Severity distribution", "severity", "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"),
                          ("3. Threat categories", "category", "COUNT(*) DESC"), ("4. Indicator types", "indicator_type", "COUNT(*) DESC"),
                          ("5. Status workflow", "status", "COUNT(*) DESC"), ("6. Sources and reliability", "source_name || ' (' || source_reliability || ')'", "COUNT(*) DESC"),
                          ("7. Countries / regions", "country", "COUNT(*) DESC")]:
    rows = q(f"SELECT {col} AS k, COUNT(*) AS n FROM threats GROUP BY k ORDER BY {order}")
    out += [f"\n## {title}\n", tbl(["Value", "Records", "Share"], [[r["k"].replace("_", " "), r["n"], pct(r["n"])] for r in rows])]
out += ["\n## 8. ATT&CK coverage (only where confidence >= 50)\n", tbl(["Tactic", "Technique", "Records"], [[r["tactic"], f'{r["technique_id"]} {r["technique"]}', r["n"]] for r in q("SELECT tactic,technique_id,technique,COUNT(*) n FROM threats WHERE technique!='' GROUP BY tactic,technique_id,technique ORDER BY n DESC")]),
        f"\nUnmapped records (insufficient evidence): **{q('SELECT COUNT(*) n FROM threats WHERE technique=\"\"')[0]['n']}**\n"]
out += ["\n## 9. Vulnerabilities\n", tbl(["Severity", "CVEs", "Avg CVSS", "Avg priority"], [[r["severity"], r["n"], r["c"], r["p"]] for r in q("SELECT severity,COUNT(*) n,ROUND(AVG(cvss_score),1) c,ROUND(AVG(priority_score),1) p FROM vulnerabilities GROUP BY severity ORDER BY p DESC")]),
        "\n**Top 5 priorities**\n\n", tbl(["CVE", "Product", "CVSS", "Exposure", "Priority"], [[r["cve_id"], r["product_category"], r["cvss_score"], r["exposure"], r["priority_score"]] for r in q("SELECT * FROM vulnerabilities ORDER BY priority_score DESC LIMIT 5")])]
out += ["\n## 10. Safety of the data\n", "- IPs only from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737 documentation ranges)\n- Domains only under `example.com`, `example.org`, `example.net`, `.invalid`\n- File hashes are random strings; they match no real file\n- CVE IDs use the unassigned `CVE-2099-*` range\n- Every description is labelled `SYNTHETIC / DEMO ONLY`\n"]
open(os.path.join(os.path.dirname(__file__), "DATASET_REPORT.md"), "w", encoding="utf-8").write("\n".join(out))
print("Wrote reports/DATASET_REPORT.md")
