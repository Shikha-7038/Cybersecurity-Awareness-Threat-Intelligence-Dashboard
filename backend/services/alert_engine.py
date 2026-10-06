"""Alert generation + correlation (fights alert fatigue). An ALERT is a prompt to investigate, NOT a confirmed incident."""
from datetime import datetime

STATUS_MAP = {"NEW": "NEW", "UNDER_REVIEW": "INVESTIGATING", "MONITORING": "MONITORING",
              "CLOSED": "RESOLVED", "FALSE_POSITIVE": "FALSE_POSITIVE"}


def generate_threat_alert(t, cluster_size=1):
    """Rule-based: returns one alert dict or None."""
    risk, conf, obs = t["risk_score"], t["confidence_score"], t["observation_count"]
    if risk >= 70 and conf >= 60:
        kind, why = "HIGH_RISK_HIGH_CONFIDENCE", "High risk backed by reliable intelligence - triage first."
    elif risk >= 70 and conf < 40:
        kind, why = "HIGH_RISK_LOW_CONFIDENCE", "Potentially serious but evidence is weak - validate before escalating."
    elif t.get("cve_id") and risk >= 60:
        kind, why = "HIGH_PRIORITY_VULNERABILITY", "Threat tied to a high-priority CVE - check patch status."
    elif obs >= 25:
        kind, why = "REPEATED_OBSERVATIONS", f"Indicator observed {obs} times - possible widespread activity."
    elif cluster_size >= 5 and risk >= 50:
        kind, why = "CORRELATED_INDICATORS", f"Part of a cluster of {cluster_size} related indicators."
    else:
        return None
    return {"threat_id": t["threat_id"], "timestamp": t["timestamp"], "alert_type": kind, "severity": t["severity"],
            "risk_score": risk, "confidence_score": conf, "indicator_value": t["indicator_value"],
            "description": f"{t['threat_name']}: {why}", "status": STATUS_MAP[t["status"]], "observation_count": 1}


def correlate_alerts(alerts, window_seconds=300):
    """Merge alerts with same (indicator, type) inside a time window: 100 events -> 1 alert, observation_count=100."""
    out, open_groups = [], {}
    for a in sorted(alerts, key=lambda x: x["timestamp"]):
        key = (a["indicator_value"], a["alert_type"])
        ts = datetime.fromisoformat(a["timestamp"])
        g = open_groups.get(key)
        if g and (ts - g["_last"]).total_seconds() <= window_seconds:
            g["observation_count"] += a["observation_count"]
            g["risk_score"] = max(g["risk_score"], a["risk_score"])
            g["_last"] = ts
        else:
            g = {**a, "_last": ts}
            open_groups[key] = g
            out.append(g)
    for g in out:
        g.pop("_last", None)
    return out
