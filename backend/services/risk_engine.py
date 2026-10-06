"""Risk, confidence and vulnerability-priority scoring. HIGH RISK != CONFIRMED COMPROMISE."""
import math

SEVERITY_BASE = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
RELIABILITY = {"A": 100, "B": 80, "C": 60, "D": 35}   # A=Highly reliable ... D=Unknown
WEIGHTS = {"severity": .30, "confidence": .25, "recency": .15, "frequency": .10, "reliability": .10, "context": .10}


def classify(score):
    """Map a 0-100 score to a severity label."""
    return ("INFORMATIONAL" if score <= 20 else "LOW" if score <= 40 else "MEDIUM" if score <= 60
            else "HIGH" if score <= 80 else "CRITICAL")


def calculate_threat_risk(base_severity, confidence, days_since_last_seen, observations, reliability, related=0):
    """Weighted 0-100 risk score (sev 30, conf 25, recency 15, freq 10, reliability 10, context 10)."""
    parts = {
        "severity": SEVERITY_BASE[base_severity],
        "confidence": confidence,
        "recency": 100 * 0.5 ** (max(days_since_last_seen, 0) / 14),   # half-life 14 days
        "frequency": min(100, 100 * math.log10(observations + 1) / 2),
        "reliability": RELIABILITY[reliability],
        "context": min(100, related * 20),
    }
    return max(0, min(100, round(sum(parts[k] * w for k, w in WEIGHTS.items()))))


def calculate_confidence(reliability, corroborating_sources=0, has_context=False):
    """How much we trust the INTELLIGENCE (0-100). Separate from risk: risk 90 + confidence 25 = weak evidence."""
    return max(0, min(100, round(RELIABILITY[reliability] * 0.5 + min(corroborating_sources, 4) * 10 + (10 if has_context else 0))))


def calculate_vulnerability_priority(cvss, asset_criticality, exposure, exploited, patch_available):
    """CVSS alone is not enough: add asset criticality (1-5), exposure, and known-exploitation evidence."""
    exp = {"internet": 1.0, "internal": 0.6, "isolated": 0.25}[exposure]
    score = cvss * 10 * 0.40 + asset_criticality * 20 * 0.25 + exp * 100 * 0.20 + (100 if exploited else 0) * 0.15
    if not patch_available:
        score += 5
    return max(0, min(100, round(score)))
