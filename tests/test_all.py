"""Automated tests (stdlib unittest, run: python -m unittest discover -s tests -v). Uses a temporary DB and synthetic data only."""
import os, sys, tempfile, unittest
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
os.environ["TI_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
import app as A
from services.ioc_validator import validate_indicator as V
from services.risk_engine import calculate_threat_risk, calculate_confidence, calculate_vulnerability_priority, classify
from services.attack_mapper import map_threat
from services.alert_engine import generate_threat_alert, correlate_alerts
from services.awareness import score_quiz, generate_learning_recommendations, awareness_level

KEY = {"X-API-Key": "analyst-demo-key"}


class Validator(unittest.TestCase):
    def test_ipv4(self): self.assertEqual(V("198.51.100.25")["indicator_type"], "IP_ADDRESS")
    def test_bad_ipv4(self): self.assertFalse(V("999.1.1.1")["valid"])
    def test_ipv6(self): self.assertTrue(V("2001:db8::1")["valid"])
    def test_domain(self): self.assertEqual(V("Login-Check.invalid".replace("invalid", "example.com"))["normalized_value"], "login-check.example.com")
    def test_bad_domain(self): self.assertFalse(V("not a domain")["valid"])
    def test_url(self): self.assertEqual(V("https://login.example.com/x")["indicator_type"], "URL")
    def test_md5(self): self.assertEqual(V("a" * 32)["indicator_type"], "FILE_HASH")
    def test_sha1(self): self.assertTrue(V("b" * 40)["valid"])
    def test_sha256(self): self.assertTrue(V("c" * 64)["valid"])
    def test_cve(self): self.assertEqual(V("cve-2099-10001")["normalized_value"], "CVE-2099-10001")
    def test_bad_cve(self): self.assertFalse(V("CVE-99-1")["valid"])
    def test_empty(self): self.assertFalse(V("")["valid"])
    def test_email_domain(self): self.assertEqual(V("a@example.org")["indicator_type"], "EMAIL_DOMAIN")


class Scoring(unittest.TestCase):
    def test_risk_range(self): self.assertTrue(0 <= calculate_threat_risk("CRITICAL", 100, 0, 100, "A", 5) <= 100)
    def test_risk_monotonic(self): self.assertGreater(calculate_threat_risk("HIGH", 80, 1, 5, "A"), calculate_threat_risk("LOW", 80, 1, 5, "A"))
    def test_recency_decay(self): self.assertGreater(calculate_threat_risk("HIGH", 80, 0, 5, "B"), calculate_threat_risk("HIGH", 80, 60, 5, "B"))
    def test_classify(self): self.assertEqual([classify(x) for x in (10, 30, 50, 70, 90)], ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_confidence(self): self.assertGreater(calculate_confidence("A", 3, True), calculate_confidence("D", 0, False))
    def test_reliability_levels(self): self.assertGreater(calculate_confidence("A"), calculate_confidence("C"))
    def test_vuln_priority_context(self):
        isolated = calculate_vulnerability_priority(9.8, 1, "isolated", False, True)
        exposed = calculate_vulnerability_priority(7.5, 5, "internet", True, True)
        self.assertGreater(exposed, isolated)


class Mapping(unittest.TestCase):
    def test_mapping(self): self.assertEqual(map_threat("PHISHING", "DOMAIN", 85)["technique_id"], "T1566")
    def test_no_mapping_low_conf(self): self.assertIsNone(map_threat("PHISHING", "DOMAIN", 20))


def _t(**o):
    t = dict(threat_id="T1", timestamp="2026-01-01T00:00:00", threat_name="x", risk_score=80, confidence_score=80, observation_count=1, indicator_value="198.51.100.1", severity="HIGH", status="NEW", cve_id="")
    return {**t, **o}


class Alerts(unittest.TestCase):
    def test_alert_generated(self): self.assertEqual(generate_threat_alert(_t())["alert_type"], "HIGH_RISK_HIGH_CONFIDENCE")
    def test_low_conf_flagged(self): self.assertEqual(generate_threat_alert(_t(confidence_score=20))["alert_type"], "HIGH_RISK_LOW_CONFIDENCE")
    def test_no_alert_low_risk(self): self.assertIsNone(generate_threat_alert(_t(risk_score=30)))
    def test_correlation_dedup(self):
        raw = [generate_threat_alert(_t(timestamp=f"2026-01-01T00:00:{i:02d}")) for i in range(50)]
        out = correlate_alerts(raw)
        self.assertEqual((len(out), out[0]["observation_count"]), (1, 50))


class Awareness(unittest.TestCase):
    QS = [{"id": 1, "category": "Phishing", "answer": 2}, {"id": 2, "category": "Passwords", "answer": 1}]
    def test_scoring(self): self.assertEqual(score_quiz(self.QS, {"1": 2, "2": 0})["overall_score"], 50)
    def test_levels(self): self.assertEqual(awareness_level(90), "Strong Awareness")
    def test_recommendation(self): self.assertIn("Phishing", generate_learning_recommendations({"Phishing": 40})[0]["recommendation"])
    def test_empty_quiz(self): self.assertEqual(score_quiz([], {})["overall_score"], 0)


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.info = A.init_db()
        cls.c = A.app.test_client()
    def test_persistence_and_load(self): self.assertGreaterEqual(self.info["loaded"], 2000)
    def test_stats(self): self.assertGreaterEqual(self.c.get("/api/dashboard/stats").get_json()["kpis"]["total"], 2000)
    def test_filter_severity(self): self.assertTrue(all(t["severity"] == "HIGH" for t in self.c.get("/api/threats?severity=high").get_json()))
    def test_filter_category(self): self.assertTrue(all(t["category"] == "PHISHING" for t in self.c.get("/api/threats?category=phishing").get_json()))
    def test_sorting(self):
        r = [t["risk_score"] for t in self.c.get("/api/threats?sort=risk&limit=20").get_json()]
        self.assertEqual(r, sorted(r, reverse=True))
    def test_search_known(self): self.assertTrue(self.c.get("/api/indicators/search?q=198.51.100.25").get_json()["known_in_demo_dataset"])
    def test_search_invalid(self): self.assertEqual(self.c.get("/api/indicators/search?q=%%%").status_code, 400)
    def test_demo_scenario(self): self.assertEqual(self.c.get("/api/threats/THR-2026-001").get_json()["indicator_value"], "login-check.invalid")
    def test_not_found(self): self.assertEqual(self.c.get("/api/threats/NOPE").status_code, 404)
    def test_notes_need_auth(self): self.assertEqual(self.c.post("/api/threats/THR-2026-001/notes", json={"note": "x"}).status_code, 401)
    def test_note_xss_escaped(self):
        self.c.post("/api/threats/THR-2026-001/notes", json={"note": "<script>x</script>"}, headers=KEY)
        notes = self.c.get("/api/threats/THR-2026-001").get_json()["notes"]
        self.assertNotIn("<script>", notes[0]["note"])
    def test_alert_status_update(self):
        aid = self.c.get("/api/alerts").get_json()[0]["alert_id"]
        self.assertEqual(self.c.put(f"/api/alerts/{aid}/status", json={"status": "monitoring"}, headers=KEY).status_code, 200)
    def test_alert_bad_status(self): self.assertEqual(self.c.put("/api/alerts/1/status", json={"status": "??"}, headers=KEY).status_code, 400)
    def test_vulns(self): self.assertGreaterEqual(len(self.c.get("/api/vulnerabilities").get_json()), 50)
    def test_modules(self): self.assertGreaterEqual(len(self.c.get("/api/awareness/modules").get_json()), 15)
    def test_quiz_size_and_no_answers(self):
        q = self.c.get("/api/quiz").get_json()
        self.assertTrue(len(q) >= 30 and "answer" not in q[0])
    def test_quiz_submit(self): self.assertIn("overall_score", self.c.post("/api/quiz/submit", json={"answers": {}}).get_json())
    def test_quiz_bad_input(self): self.assertEqual(self.c.post("/api/quiz/submit", json={}).status_code, 400)


class EmptyDataset(unittest.TestCase):
    def test_empty_csv(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "e.csv")
        open(p, "w").write(",".join(["threat_id", "timestamp", "threat_name", "threat_category", "indicator_type", "indicator_value", "source_name", "confidence_score", "severity", "risk_score", "status", "first_seen", "last_seen", "country_or_region_optional", "description", "mitre_tactic_optional", "mitre_technique_optional", "cve_id_optional", "campaign_id", "observation_count", "source_reliability", "technique_id_optional"]) + "\n")
        self.assertEqual(A.init_db(p, os.path.join(d, "none.csv"))["loaded"], 0)
        self.assertEqual(A.app.test_client().get("/api/dashboard/stats").get_json()["kpis"]["total"], 0)
        A.init_db()


if __name__ == "__main__":
    unittest.main()
