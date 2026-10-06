"""Flask backend: loads synthetic CSVs into SQLite (pipeline: validate -> normalize -> alert -> correlate) and serves the REST API + dashboard.
Run:  python data/generate_threat_data.py && python backend/app.py"""
import csv, html, json, os, sqlite3, time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, g, jsonify, request, send_from_directory

from services.ioc_validator import validate_indicator
from services.alert_engine import generate_threat_alert, correlate_alerts
from services.risk_engine import calculate_vulnerability_priority
from services.awareness import score_quiz

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.environ.get("TI_DB", os.path.join(ROOT, "threat_intel.db"))
KEYS = {os.environ.get("ANALYST_KEY", "analyst-demo-key"): "analyst", os.environ.get("ADMIN_KEY", "admin-demo-key"): "admin"}
app = Flask(__name__, static_folder=os.path.join(ROOT, "frontend"), static_url_path="")
_hits = defaultdict(list)


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS threats(threat_id TEXT PRIMARY KEY, timestamp TEXT, threat_name TEXT, category TEXT, indicator_type TEXT, indicator_value TEXT,
 source_name TEXT, source_reliability TEXT, confidence_score INT, severity TEXT, risk_score INT, status TEXT, first_seen TEXT, last_seen TEXT, country TEXT,
 description TEXT, tactic TEXT, technique TEXT, technique_id TEXT, cve_id TEXT, campaign_id TEXT, observation_count INT);
CREATE INDEX IF NOT EXISTS ix_t_ind ON threats(indicator_value); CREATE INDEX IF NOT EXISTS ix_t_sev ON threats(severity);
CREATE INDEX IF NOT EXISTS ix_t_cat ON threats(category); CREATE INDEX IF NOT EXISTS ix_t_camp ON threats(campaign_id);
CREATE TABLE IF NOT EXISTS alerts(alert_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, timestamp TEXT, alert_type TEXT, severity TEXT, risk_score INT,
 confidence_score INT, description TEXT, status TEXT, indicator_value TEXT, observation_count INT);
CREATE TABLE IF NOT EXISTS notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, note TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS vulnerabilities(cve_id TEXT PRIMARY KEY, product_category TEXT, severity TEXT, cvss_score REAL, published_date TEXT, patch_available INT,
 exploitation_status_demo TEXT, asset_criticality INT, exposure TEXT, priority_score INT, description TEXT);
CREATE TABLE IF NOT EXISTS quiz_results(result_id INTEGER PRIMARY KEY AUTOINCREMENT, overall_score INT, created_at TEXT);
"""


def init_db(csv_path=None, vuln_path=None):
    """(Re)build the database from the synthetic CSVs. Invalid indicators are rejected, valid ones normalised."""
    csv_path = csv_path or os.path.join(ROOT, "data", "threat_intelligence_dataset.csv")
    vuln_path = vuln_path or os.path.join(ROOT, "data", "vulnerabilities.csv")
    con = sqlite3.connect(DB_PATH)
    con.executescript("DROP TABLE IF EXISTS threats; DROP TABLE IF EXISTS alerts; DROP TABLE IF EXISTS vulnerabilities;" + SCHEMA)
    rows, rejected = [], 0
    for r in csv.DictReader(open(csv_path, encoding="utf-8")):
        v = validate_indicator(r["indicator_value"])
        if not v["valid"]:
            rejected += 1
            continue
        rows.append((r["threat_id"], r["timestamp"], r["threat_name"], r["threat_category"], v["indicator_type"], v["normalized_value"], r["source_name"],
                     r["source_reliability"], int(r["confidence_score"]), r["severity"], int(r["risk_score"]), r["status"], r["first_seen"], r["last_seen"],
                     r["country_or_region_optional"], r["description"], r["mitre_tactic_optional"], r["mitre_technique_optional"], r["technique_id_optional"],
                     r["cve_id_optional"], r["campaign_id"], int(r["observation_count"])))
    con.executemany("INSERT OR REPLACE INTO threats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    if os.path.exists(vuln_path):
        for r in csv.DictReader(open(vuln_path, encoding="utf-8")):
            pa = r["patch_available"] == "True"
            pr = calculate_vulnerability_priority(float(r["cvss_score"]), int(r["asset_criticality"]), r["exposure"], r["exploitation_status_demo"] == "exploited_in_demo", pa)
            con.execute("INSERT OR REPLACE INTO vulnerabilities VALUES(?,?,?,?,?,?,?,?,?,?,?)", (r["cve_id"], r["product_category"], r["severity"], float(r["cvss_score"]),
                        r["published_date"], int(pa), r["exploitation_status_demo"], int(r["asset_criticality"]), r["exposure"], pr, r["description"]))
    # alert pipeline: generate -> correlate (alert-fatigue reduction)
    csize = Counter(x[20] for x in rows)
    cols = ["threat_id", "timestamp", "threat_name", "category", "indicator_type", "indicator_value", "source_name", "source_reliability", "confidence_score", "severity",
            "risk_score", "status", "first_seen", "last_seen", "country", "description", "tactic", "technique", "technique_id", "cve_id", "campaign_id", "observation_count"]
    raw = [a for a in (generate_threat_alert(dict(zip(cols, x)), csize[x[20]]) for x in rows) if a]
    for a in correlate_alerts(raw, window_seconds=7 * 86400):
        con.execute("INSERT INTO alerts(threat_id,timestamp,alert_type,severity,risk_score,confidence_score,description,status,indicator_value,observation_count) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (a["threat_id"], a["timestamp"], a["alert_type"], a["severity"], a["risk_score"], a["confidence_score"], a["description"], a["status"], a["indicator_value"], a["observation_count"]))
    con.commit()
    con.close()
    return {"loaded": len(rows), "rejected": rejected}


# ---------- security helpers ----------
def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            role = KEYS.get(request.headers.get("X-API-Key", ""))
            if not role:
                return jsonify(error="Authentication required (X-API-Key)"), 401
            if role not in roles and role != "admin":
                return jsonify(error="Forbidden for your role"), 403
            return fn(*a, **kw)
        return wrapper
    return deco


@app.before_request
def rate_limit():
    ip, now = request.remote_addr, time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < 60] + [now]
    if len(_hits[ip]) > 1200:
        return jsonify(error="Rate limit exceeded"), 429


def clean(s, n=2000):
    return html.escape("".join(ch for ch in str(s) if ch.isprintable() or ch in "\n\t")[:n].strip())


def rows(q, args=()):
    return [dict(r) for r in db().execute(q, args).fetchall()]


# ---------- API ----------
@app.get("/api/threats")
def list_threats():
    a, where, args = request.args, [], []
    for col, key in (("severity", "severity"), ("category", "category"), ("indicator_type", "indicator_type"), ("status", "status")):
        if a.get(key):
            where.append(f"{col}=?")
            args.append(a[key].upper())
    if a.get("min_risk"): where.append("risk_score>=?"); args.append(int(a["min_risk"]))
    if a.get("min_confidence"): where.append("confidence_score>=?"); args.append(int(a["min_confidence"]))
    if a.get("q"): where.append("(indicator_value LIKE ? OR threat_name LIKE ? OR threat_id LIKE ?)"); args += [f"%{a['q']}%"] * 3
    order = {"newest": "timestamp DESC", "risk": "risk_score DESC", "confidence": "confidence_score DESC", "observed": "observation_count DESC"}.get(a.get("sort", "newest"), "timestamp DESC")
    limit = min(int(a.get("limit", 50)), 500)
    offset = max(int(a.get("offset", 0)), 0)
    sql = "SELECT * FROM threats" + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY {order} LIMIT ? OFFSET ?"
    return jsonify(rows(sql, args + [limit, offset]))


@app.get("/api/threats/<tid>")
def threat_detail(tid):
    t = rows("SELECT * FROM threats WHERE threat_id=?", (tid,))
    if not t:
        return jsonify(error="Threat not found"), 404
    t = t[0]
    return jsonify({**t, "related_indicators": rows("SELECT threat_id,indicator_type,indicator_value,risk_score FROM threats WHERE campaign_id=? AND threat_id!=? ORDER BY risk_score DESC LIMIT 12", (t["campaign_id"], tid)),
                    "related_alerts": rows("SELECT * FROM alerts WHERE threat_id=? OR indicator_value=?", (tid, t["indicator_value"])),
                    "notes": rows("SELECT * FROM notes WHERE threat_id=? ORDER BY note_id DESC", (tid,)),
                    "timeline": [{"step": "First Seen", "at": t["first_seen"]}, {"step": "Last Observation", "at": t["last_seen"]}, {"step": t["status"].replace("_", " ").title(), "at": t["timestamp"]}],
                    "recommended_actions": ["Review related internal logs", "Check for authorized sightings", "Monitor for related indicators", "Increase awareness for the affected category", "Do NOT contact or visit the indicator"]})


@app.post("/api/threats/<tid>/notes")
@require_role("analyst")
def add_note(tid):
    note = clean((request.get_json(silent=True) or {}).get("note", ""))
    if not note:
        return jsonify(error="note is required"), 400
    if not rows("SELECT 1 FROM threats WHERE threat_id=?", (tid,)):
        return jsonify(error="Threat not found"), 404
    db().execute("INSERT INTO notes(threat_id,note,created_at) VALUES(?,?,?)", (tid, note, datetime.now().isoformat(timespec="seconds")))
    db().commit()
    return jsonify(ok=True), 201


@app.get("/api/indicators/search")
def search_indicator():
    """Database lookup ONLY - never connects to the searched IP/domain/URL."""
    v = validate_indicator(request.args.get("q", ""))
    if not v["valid"]:
        return jsonify(error="Invalid indicator", **v), 400
    hits = rows("SELECT * FROM threats WHERE indicator_value=? ORDER BY risk_score DESC", (v["normalized_value"],))
    if not hits:
        return jsonify(known_in_demo_dataset=False, **v)
    top = hits[0]
    return jsonify(known_in_demo_dataset=True, **v, risk=top["risk_score"], severity=top["severity"], confidence=top["confidence_score"], category=top["category"],
                   first_seen=min(h["first_seen"] for h in hits), last_seen=max(h["last_seen"] for h in hits), status=top["status"], threat_id=top["threat_id"],
                   observations=sum(h["observation_count"] for h in hits),
                   note="High risk does not equal confirmed compromise. Analyst validation required.")


@app.get("/api/dashboard/stats")
def stats():
    T = rows("SELECT * FROM threats")
    cnt = lambda k, src=T: dict(Counter(x[k] for x in src if x[k]).most_common())
    now = datetime.now()
    trend = Counter(x["timestamp"][:10] for x in T)
    days = [(now - timedelta(days=i)).date().isoformat() for i in range(29, -1, -1)]
    vul = rows("SELECT * FROM vulnerabilities ORDER BY priority_score DESC")
    al = rows("SELECT * FROM alerts")
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    return jsonify({
        "kpis": {"total": len(T), "critical": sum(x["severity"] == "CRITICAL" for x in T), "high": sum(x["severity"] == "HIGH" for x in T),
                 "active_indicators": len({x["indicator_value"] for x in T if x["status"] in ("NEW", "UNDER_REVIEW", "MONITORING")}),
                 "open_investigations": sum(x["status"] == "UNDER_REVIEW" for x in T), "avg_confidence": round(sum(x["confidence_score"] for x in T) / max(len(T), 1)),
                 "vulnerabilities": len(vul), "open_alerts": sum(a["status"] in ("NEW", "INVESTIGATING") for a in al)},
        "trend": {"labels": days, "values": [trend.get(d, 0) for d in days], "high": [sum(1 for x in T if x["timestamp"][:10] == d and x["severity"] in ("HIGH", "CRITICAL")) for d in days]},
        "severity": {s: sum(x["severity"] == s for x in T) for s in sev_order}, "category": cnt("category"), "ioc_types": cnt("indicator_type"), "status": cnt("status"),
        "tactics": cnt("tactic"), "techniques": dict(Counter(f"{x['technique_id']} {x['technique']}" for x in T if x["technique"]).most_common(8)), "countries": dict(Counter(x["country"] for x in T).most_common(8)),
        "risk_hist": [sum(i * 10 <= x["risk_score"] < (i + 1) * 10 + (1 if i == 9 else 0) for x in T) for i in range(10)],
        "conf_hist": [sum(i * 10 <= x["confidence_score"] < (i + 1) * 10 + (1 if i == 9 else 0) for x in T) for i in range(10)],
        "vuln_severity": {s: sum(v["severity"] == s for v in vul) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}, "top_vulns": vul[:6],
        "top_indicators": sorted(({"value": v, "type": t, "obs": o, "risk": r} for v, t, o, r in db().execute("SELECT indicator_value,indicator_type,SUM(observation_count),MAX(risk_score) FROM threats GROUP BY indicator_value ORDER BY SUM(observation_count) DESC LIMIT 7")), key=lambda x: -x["obs"]),
        "hierarchy": {"observations": sum(x["observation_count"] for x in T), "indicators": len({x["indicator_value"] for x in T}), "alerts": len(al), "threats": len({x["campaign_id"] for x in T}),
                      "incidents": sum(1 for a in al if a["status"] == "INVESTIGATING" and a["severity"] == "CRITICAL")},
        "alert_types": dict(Counter(a["alert_type"] for a in al).most_common()), "alert_status": dict(Counter(a["status"] for a in al).most_common()),
        "sources": rows("SELECT source_name AS name, COUNT(*) AS records, ROUND(AVG(confidence_score)) AS avg_conf, source_reliability AS reliability FROM threats GROUP BY source_name ORDER BY records DESC"),
        "matrix": {t: dict(Counter(f"{x['technique_id']} {x['technique']}" for x in T if x["tactic"] == t)) for t in sorted({x["tactic"] for x in T if x["tactic"]})},
        "campaigns": rows("SELECT campaign_id, category, COUNT(*) AS records, MAX(risk_score) AS max_risk, SUM(observation_count) AS obs FROM threats GROUP BY campaign_id ORDER BY records DESC LIMIT 8"),
        "recent_alerts": rows("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 9")})


@app.get("/api/alerts")
def list_alerts():
    st = request.args.get("status")
    return jsonify(rows("SELECT * FROM alerts" + (" WHERE status=?" if st else "") + " ORDER BY risk_score DESC LIMIT 200", (st.upper(),) if st else ()))


@app.put("/api/alerts/<int:aid>/status")
@require_role("analyst")
def alert_status(aid):
    s = str((request.get_json(silent=True) or {}).get("status", "")).upper()
    if s not in ("NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"):
        return jsonify(error="Invalid status"), 400
    cur = db().execute("UPDATE alerts SET status=? WHERE alert_id=?", (s, aid))
    db().commit()
    return (jsonify(ok=True), 200) if cur.rowcount else (jsonify(error="Alert not found"), 404)


@app.get("/api/vulnerabilities")
def vulns():
    return jsonify(rows("SELECT * FROM vulnerabilities ORDER BY priority_score DESC"))


@app.get("/api/awareness/modules")
def modules():
    return send_from_directory(os.path.join(ROOT, "awareness"), "modules.json")


def _quiz():
    return json.load(open(os.path.join(ROOT, "awareness", "quiz_questions.json"), encoding="utf-8"))


@app.get("/api/quiz")
def quiz():
    return jsonify([{k: v for k, v in q.items() if k not in ("answer", "why")} for q in _quiz()])


@app.post("/api/quiz/submit")
def quiz_submit():
    ans = (request.get_json(silent=True) or {}).get("answers")
    if not isinstance(ans, dict):
        return jsonify(error="answers object required"), 400
    qs = _quiz()
    res = score_quiz(qs, ans)
    res["review"] = [{"id": q["id"], "correct": ans.get(str(q["id"])) == q["answer"], "why": q["why"]} for q in qs]
    db().execute("INSERT INTO quiz_results(overall_score,created_at) VALUES(?,?)", (res["overall_score"], datetime.now().isoformat(timespec="seconds")))
    db().commit()
    return jsonify(res)


@app.get("/api/demo-keys")
def demo_keys():
    """DEMO ONLY: lets the UI act as an analyst. Remove/disable in any real deployment."""
    return jsonify(analyst=next(k for k, r in KEYS.items() if r == "analyst"))


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("Building database:", init_db())
    app.run(debug=False, port=5000)
