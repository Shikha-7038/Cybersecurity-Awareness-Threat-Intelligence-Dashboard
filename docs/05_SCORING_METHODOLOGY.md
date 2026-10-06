# 05 · Scoring Methodology

## Threat risk score (0–100)
| Factor | Weight | How it is derived |
|---|---|---|
| Base severity | 30% | INFORMATIONAL 10, LOW 30, MEDIUM 50, HIGH 75, CRITICAL 95 |
| Confidence | 25% | 0–100 trust in the intelligence |
| Recency | 15% | `100 × 0.5^(days/14)` — half-life of 14 days |
| Observation frequency | 10% | `100 × log10(obs+1) / 2`, capped at 100 |
| Source reliability | 10% | A 100, B 80, C 60, D 35 |
| Related indicators | 10% | 20 points per related indicator, capped at 100 |

## Severity labels
| Score | Label |
|---|---|
| 0–20 | INFORMATIONAL |
| 21–40 | LOW |
| 41–60 | MEDIUM |
| 61–80 | HIGH |
| 81–100 | CRITICAL |

## Confidence score
- Starts from half of the source reliability value
- +10 per corroborating source (max 4)
- +10 when useful context exists
- Clamped to 0–100

| Example | Meaning |
|---|---|
| Risk 90, confidence 25 | Potentially serious but weak evidence — validate first |
| Risk 70, confidence 85 | Credible and serious — triage now |

## Source reliability
| Grade | Meaning | Synthetic sources |
|---|---|---|
| A | Highly reliable | Internal SOC |
| B | Usually reliable | Security Vendor, Research Report |
| C | Fairly reliable | Public Threat Feed |
| D | Unknown / unproven | Community Submission, Unknown Source |

## Vulnerability priority (0–100)
| Factor | Weight |
|---|---|
| CVSS × 10 | 40% |
| Asset criticality (1–5) × 20 | 25% |
| Exposure: internet 100, internal 60, isolated 25 | 20% |
| Known exploitation (demo flag) | 15% |
| No patch available | +5 |

## Alert rules
| Alert type | Condition |
|---|---|
| HIGH_RISK_HIGH_CONFIDENCE | risk ≥ 70 and confidence ≥ 60 |
| HIGH_RISK_LOW_CONFIDENCE | risk ≥ 70 and confidence < 40 |
| HIGH_PRIORITY_VULNERABILITY | CVE attached and risk ≥ 60 |
| REPEATED_OBSERVATIONS | observation count ≥ 25 |
| CORRELATED_INDICATORS | cluster of ≥ 5 records and risk ≥ 50 |

**Correlation:** alerts with the same indicator and type within the time window merge into one alert with a summed observation count and the maximum risk.

## ATT&CK mapping
- Only maps when confidence ≥ 50
- Category → tactic/technique table is in the ATT&CK tab and `attack_mapper.py`
- Malware indicators that are domains/IPs map to Command and Control (T1071)

## Limitations
- Weights are teaching defaults, not tuned on real incidents
- Scores rank work; they do not prove compromise
