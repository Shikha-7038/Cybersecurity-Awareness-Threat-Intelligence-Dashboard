# Project Report — Cybersecurity Awareness & Threat Intelligence Dashboard

## 1. Abstract
This project implements a defensive, SOC-style dashboard that ingests synthetic threat intelligence, validates and scores indicators, correlates alerts, maps threats to MITRE ATT&CK, prioritises vulnerabilities and delivers security-awareness training. It is built with Flask, SQLite and Chart.js, and never contacts any indicator.

## 2. Problem statement
| Problem | Effect |
|---|---|
| Too many indicators and alerts | Alert fatigue, missed priorities |
| Scores without context | Over-reaction or complacency |
| Low security awareness | Phishing and weak passwords remain effective |
| No safe practice environment | Students cannot explore realistic workflows |

## 3. Objectives
- Validate and normalise IOCs
- Score risk and confidence separately
- Correlate repeated observations into fewer alerts
- Map to ATT&CK only with enough evidence
- Prioritise CVEs with asset and exposure context
- Provide a scored awareness quiz with recommendations

## 4. Methodology
1. Requirements from the project brief
2. Safe synthetic dataset design (reserved IPs, example domains, `CVE-2099-*`)
3. Service modules for validation, scoring, mapping, alerts, quiz
4. SQLite storage and Flask REST API
5. Tabbed dashboard UI with lazy chart rendering
6. Unit and API testing
7. Documentation and reporting

## 5. System design
| Layer | Technology |
|---|---|
| UI | HTML, CSS, JavaScript, Chart.js |
| API | Flask |
| Logic | Python service modules |
| Storage | SQLite |
| Data | Generated CSV files |

Details: `docs/02_ARCHITECTURE.md`, `docs/03_DATABASE_SCHEMA.md`, `docs/04_API_REFERENCE.md`.

## 6. Implementation highlights
| Component | Highlights |
|---|---|
| IOC validator | IPv4/IPv6, domain, URL, MD5/SHA1/SHA256, email domain, CVE |
| Risk engine | Six weighted factors with 14-day recency half-life |
| Confidence | Reliability grade + corroboration + context |
| Alert engine | Five rules, time-window correlation |
| ATT&CK mapper | Ten categories, confidence threshold 50 |
| Vulnerability priority | CVSS, asset criticality, exposure, exploitation, patch |
| Dashboard | 9 tabs, 10+ charts, filters, pagination, alert actions, notes |
| Awareness | 15 modules, 40 questions, per-category recommendations |

## 7. Results
| Measure | Result |
|---|---|
| Threat records | 2,202 |
| Unique indicators | 1,759 |
| Alerts after correlation | 1,368 |
| Synthetic CVEs | 60 |
| Automated tests | 49 passing |

More numbers: `reports/DATASET_REPORT.md`. Test detail: `reports/TEST_REPORT.md`.

## 8. Ethics and safety
- All data synthetic and labelled
- No scanning, exploitation or malware
- Lookups are database-only
- Input validation, parameterised SQL, escaping, API keys, rate limiting

## 9. Limitations
- Synthetic data demonstrates workflow, not real-world accuracy
- Scoring weights are teaching defaults
- Demo key endpoint and in-memory rate limiter are not production-grade
- Chart.js loads from a CDN
- No automated browser tests

## 10. Future work
| Idea | Benefit |
|---|---|
| STIX/TAXII import | Standard intelligence exchange |
| SIEM integration | Real alert sources |
| IOC expiry and aging | Fewer stale indicators |
| PostgreSQL + Docker | Deployable stack |
| Real authentication | Production readiness |
| React/Recharts front end | Component-based UI |

## 11. Conclusion
The project shows how prioritisation, correlation and explainable scoring reduce noise, and how awareness content complements technical intelligence, all in a safe, reproducible environment.
