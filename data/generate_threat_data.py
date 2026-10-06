"""Generate SAFE synthetic threat data. Only reserved/documentation indicators are used:
IPs from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; domains under example.com/.org/.net/.invalid.
File hashes are random strings labelled SYNTHETIC / DEMO ONLY. Nothing here is a real threat."""
import csv, os, random, sys, hashlib
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from services.risk_engine import calculate_threat_risk, calculate_confidence, classify
from services.attack_mapper import map_threat

random.seed(2026)
HERE = os.path.dirname(__file__)
N = 2200
NOW = datetime.now().replace(microsecond=0)

SOURCES = {"Internal SOC": "A", "Security Vendor": "B", "Research Report": "B",
           "Public Threat Feed": "C", "Community Submission": "D", "Unknown Source": "D"}
SRC_W = [20, 20, 12, 28, 12, 8]
CATS = {  # category: (threat names, indicator-type weights, base severity weights)
    "PHISHING": (["Synthetic Credential Phishing Campaign", "Synthetic Invoice Lure Wave", "Synthetic QR-Code Lure"], {"DOMAIN": 3, "URL": 3, "EMAIL_DOMAIN": 3, "IP_ADDRESS": 1}, [0, 1, 3, 4, 1]),
    "MALWARE": (["Synthetic Loader Activity", "Synthetic Info-Stealer Beacon", "Synthetic Trojan Dropper"], {"FILE_HASH": 4, "DOMAIN": 2, "IP_ADDRESS": 2}, [0, 1, 3, 4, 2]),
    "RANSOMWARE": (["Synthetic Ransomware Precursor", "Synthetic Extortion Notice Pattern"], {"FILE_HASH": 3, "IP_ADDRESS": 2, "DOMAIN": 1}, [0, 0, 1, 3, 4]),
    "CREDENTIAL_THEFT": (["Synthetic Credential Harvest Page", "Synthetic Password Spray Source"], {"DOMAIN": 3, "IP_ADDRESS": 3, "URL": 2}, [0, 1, 3, 3, 1]),
    "SOCIAL_ENGINEERING": (["Synthetic Pretext Call Pattern", "Synthetic Fake Support Message"], {"EMAIL_DOMAIN": 3, "DOMAIN": 2}, [1, 3, 3, 1, 0]),
    "NETWORK_THREATS": (["Synthetic Port Sweep Source", "Synthetic Beaconing Pattern"], {"IP_ADDRESS": 6, "DOMAIN": 1}, [1, 3, 3, 2, 0]),
    "WEB_THREATS": (["Synthetic Drive-by Redirect Chain", "Synthetic Malvertising Domain"], {"URL": 4, "DOMAIN": 3}, [1, 2, 3, 2, 1]),
    "DATA_EXPOSURE": (["Synthetic Public Bucket Exposure", "Synthetic Leaked Credential Dump Mention"], {"DOMAIN": 2, "URL": 2, "EMAIL_DOMAIN": 2}, [1, 2, 3, 3, 1]),
    "ACCOUNT_TAKEOVER_RISK": (["Synthetic Impossible-Travel Login", "Synthetic MFA Fatigue Pattern"], {"IP_ADDRESS": 4, "EMAIL_DOMAIN": 2}, [1, 2, 3, 3, 1]),
    "VULNERABILITY_EXPLOITATION": (["Synthetic Exploit-Attempt Pattern (awareness)", "Synthetic Unpatched Exposure Signal"], {"IP_ADDRESS": 3, "CVE_ID": 4, "URL": 1}, [0, 1, 2, 4, 3]),
}
CAT_W = [14, 14, 8, 11, 9, 11, 10, 8, 9, 6]
SEVS = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
STAT_W = [30, 20, 25, 18, 7]
COUNTRIES = ["US", "IN", "DE", "GB", "BR", "SG", "AU", "JP", "FR", "ZA", "CA", "NL"]
WORDS = ["secure", "login", "verify", "portal", "update", "account", "cloud", "mail", "pay", "docs", "sync", "auth", "help", "check", "invoice", "track"]
TLDS = ["example.com", "example.org", "example.net", "invalid"]


def make_cves(n=60):
    prods = ["Web Server", "VPN Gateway", "Email Platform", "Database", "Browser", "OS Kernel", "CMS Plugin", "Router Firmware", "Cloud SDK", "Office Suite"]
    rows = []
    for i in range(n):
        cvss = round(random.choice([random.uniform(3, 6.9), random.uniform(7, 8.9), random.uniform(9, 10)]), 1)
        sev = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
        rows.append({"cve_id": f"CVE-2099-{10001 + i}", "product_category": random.choice(prods), "severity": sev, "cvss_score": cvss,
                     "published_date": (NOW - timedelta(days=random.randint(1, 120))).date().isoformat(),
                     "patch_available": random.random() < 0.7, "exploitation_status_demo": random.choice(["none_observed", "none_observed", "poc_discussed", "exploited_in_demo"]),
                     "asset_criticality": random.randint(1, 5), "exposure": random.choice(["internet", "internal", "isolated"]),
                     "description": "SYNTHETIC / DEMO ONLY vulnerability record for awareness. No exploit details."})
    return rows


def indicator(kind, cves):
    w = random.choice(WORDS) + "-" + random.choice(WORDS)
    if kind == "IP_ADDRESS": return f"{random.choice(['192.0.2', '198.51.100', '203.0.113'])}.{random.randint(1, 254)}"
    if kind == "DOMAIN": return f"{w}.{random.choice(TLDS)}"
    if kind == "URL": return f"https://{w}.{random.choice(TLDS)}/{random.choice(['login', 'verify', 'files', 'update'])}"
    if kind == "EMAIL_DOMAIN": return f"noreply@{w}.{random.choice(TLDS)}"
    if kind == "CVE_ID": return random.choice(cves)["cve_id"]
    return hashlib.sha256(os.urandom(8) + w.encode()).hexdigest()   # SYNTHETIC / DEMO ONLY


def build():
    cves = make_cves()
    campaigns = []
    for c in range(1, 141):
        cat = random.choices(list(CATS), CAT_W)[0]
        campaigns.append((f"CMP-{c:03d}", cat, NOW - timedelta(days=random.randint(2, 88))))
    rows = []
    for i in range(1, N + 1):
        cid, cat, start = random.choice(campaigns)
        names, itypes, sevw = CATS[cat]
        itype = random.choices(list(itypes), list(itypes.values()))[0]
        src = random.choices(list(SOURCES), SRC_W)[0]
        rel = SOURCES[src]
        first = min(start + timedelta(hours=random.randint(0, 240)), NOW - timedelta(hours=1))
        last = min(first + timedelta(hours=random.randint(0, 300)), NOW)
        obs = int(random.choice([1, 1, 2, 3, 5, 8, 13, 21, 34, 55]))
        has_ctx = random.random() < 0.6
        conf = min(100, calculate_confidence(rel, random.randint(0, 3), has_ctx) + random.randint(-8, 8))
        base = random.choices(SEVS, sevw)[0]
        days = (NOW - last).total_seconds() / 86400
        risk = calculate_threat_risk(base, conf, days, obs, rel, related=random.randint(0, 4))
        mp = map_threat(cat, itype, conf)
        rows.append({
            "threat_id": f"THR-2026-{i + 100:04d}", "timestamp": last.isoformat(), "threat_name": random.choice(names),
            "threat_category": cat, "indicator_type": itype, "indicator_value": indicator(itype, cves), "source_name": src,
            "confidence_score": conf, "severity": classify(risk), "risk_score": risk, "status": random.choices(STATUSES, STAT_W)[0],
            "first_seen": first.isoformat(), "last_seen": last.isoformat(), "country_or_region_optional": random.choice(COUNTRIES),
            "description": f"SYNTHETIC / DEMO ONLY: {cat.replace('_', ' ').title()} observation for defensive awareness. Indicator is a reserved/example value.",
            "mitre_tactic_optional": mp["tactic"] if mp else "", "mitre_technique_optional": mp["technique"] if mp else "",
            "cve_id_optional": random.choice(cves)["cve_id"] if cat == "VULNERABILITY_EXPLOITATION" else "",
            "campaign_id": cid, "observation_count": obs, "source_reliability": rel,
            "technique_id_optional": mp["technique_id"] if mp else ""})
    # Pinned safe demo scenario from the project brief (THR-2026-001) + its related IP.
    t0 = (NOW - timedelta(days=6)).isoformat()
    pin = dict(rows[0], threat_id="THR-2026-001", timestamp=t0, threat_name="Synthetic Credential Phishing Campaign", threat_category="PHISHING",
               indicator_type="DOMAIN", indicator_value="login-check.invalid", source_name="Internal SOC", confidence_score=85,
               severity="HIGH", risk_score=78, status="MONITORING", first_seen=(NOW - timedelta(days=12)).isoformat(), last_seen=t0,
               description="SYNTHETIC / DEMO ONLY: Indicator appears in multiple synthetic phishing observations. Do NOT visit the domain.",
               mitre_tactic_optional="Initial Access", mitre_technique_optional="Phishing", technique_id_optional="T1566",
               cve_id_optional="", campaign_id="CMP-DEMO", observation_count=14, source_reliability="A")
    rel_ip = dict(pin, threat_id="THR-2026-002", indicator_type="IP_ADDRESS", indicator_value="198.51.100.25", threat_name="Synthetic Phishing Hosting Infrastructure", risk_score=78, severity="HIGH", confidence_score=85)
    return [pin, rel_ip] + rows, cves


def write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    threats, cves = build()
    write(os.path.join(HERE, "threat_intelligence_dataset.csv"), threats)
    write(os.path.join(HERE, "vulnerabilities.csv"), cves)
    print(f"Wrote {len(threats)} synthetic threat records and {len(cves)} synthetic CVEs (SYNTHETIC / DEMO ONLY).")
