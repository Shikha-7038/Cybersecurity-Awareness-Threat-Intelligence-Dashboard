# 🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard

A **defensive** SOC-style dashboard that combines synthetic threat intelligence with a security-awareness centre.

> **Safety:** all data is synthetic / demo only. Nothing scans, probes or contacts any IP, domain or URL, and no malware or exploit code is included. Indicator search is a database lookup.

## Table of contents
- [Features](#features) · [Dashboard tabs](#dashboard-tabs) · [Tech stack](#tech-stack) · [Project structure](#project-structure)
- [Setup](#setup-and-run) · [Demo walkthrough](#demo-walkthrough) · [Scoring](#scoring-summary) · [API](#api-summary)
- [Security](#security-notes) · [Testing](#testing) · [Documentation](#documentation-and-reports) · [Limitations](#limitations) · [Future work](#future-work)

## Features
- IOC validation and normalisation (IP, domain, URL, hash, email domain, CVE)
- Separate **risk** and **confidence** scores with source reliability (A–D)
- Alert generation and correlation to reduce alert fatigue
- Conservative MITRE ATT&CK mapping (only when confidence ≥ 50)
- Vulnerability prioritisation using CVSS, asset criticality, exposure and exploitation
- Security awareness modules and a 40-question quiz with recommendations
- Tabbed, data-dense dashboard with 10+ charts

## Dashboard tabs
| Tab | Contents |
|---|---|
| 📊 Overview | KPIs, intelligence hierarchy, trend, severity, categories, IOC types, tactics, alerts, top indicators |
| 🧾 Threat Intelligence | Filters, sorting, pagination, risk/confidence histograms, sources, campaigns, detail view with notes |
| 🔎 IOC Search | Validated lookup, samples, safe-handling rules, highest-risk indicators |
| 🚨 Alerts | Alert charts, fatigue funnel, queue with status changes |
| 🩹 Vulnerabilities | Charts, fix-first list, priority formula, full table |
| 🗺️ ATT&CK | Tactics, techniques, matrix, mapping policy |
| 🎓 Awareness | 15 modules, do/don't, phishing red flags |
| 📝 Quiz | 40 questions, scores, recommendations |
| ℹ️ About | Stack, weights, ethics |

## Tech stack
| Layer | Technology |
|---|---|
| Backend | Python 3.9+, Flask |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript, Chart.js (CDN) |
| Testing | `unittest` |

## Project structure
```
├── backend/           app.py + services/ (validator, risk, ATT&CK, alerts, awareness)
├── frontend/          index.html (tabbed UI)
├── data/              generate_threat_data.py + generated CSVs
├── awareness/         modules.json, quiz_questions.json
├── tests/             test_all.py (49 tests)
├── docs/              11 documentation files
├── reports/           project, test, dataset reports + LinkedIn draft
├── requirements.txt · .env.example · .gitignore
```

## Setup and run
**Requirements:** Python 3.9+, internet access for the Chart.js CDN.
```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python data/generate_threat_data.py  # creates the synthetic CSVs
python backend/app.py                # builds SQLite DB and starts the server
```
Open **http://127.0.0.1:5000**.

| Optional step | Command |
|---|---|
| Run tests | `python -m unittest discover -s tests -v` |
| Rebuild data | Delete `threat_intel.db`, rerun the generator, restart |
| Refresh dataset report | `python reports/generate_dataset_report.py` |
| Change keys / DB path | Copy `.env.example` values into your environment |

## Demo walkthrough
1. **Overview** — read the KPIs and hierarchy
2. **Threat Intelligence** — filter `HIGH`, open a record, add a note
3. **IOC Search** — try `198.51.100.25` and `login-check.invalid`; then `999.1.1.1` (invalid)
4. **Alerts** — change a status
5. **Vulnerabilities** — review the fix-first list
6. **ATT&CK** — inspect the matrix
7. **Quiz** — complete it and read the recommendations

## Scoring summary
| Risk factor | Weight |
|---|---|
| Base severity | 30% |
| Confidence | 25% |
| Recency (14-day half-life) | 15% |
| Observation frequency | 10% |
| Source reliability | 10% |
| Related indicators | 10% |

| Score | Severity |
|---|---|
| 0–20 | Informational |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

Full method: [docs/05_SCORING_METHODOLOGY.md](docs/05_SCORING_METHODOLOGY.md).

## API summary
| Method | Path | Auth |
|---|---|---|
| GET | `/api/threats`, `/api/threats/{id}` | – |
| POST | `/api/threats/{id}/notes` | analyst key |
| GET | `/api/indicators/search?q=` | – |
| GET | `/api/dashboard/stats`, `/api/alerts`, `/api/vulnerabilities` | – |
| PUT | `/api/alerts/{id}/status` | analyst key |
| GET | `/api/awareness/modules`, `/api/quiz` | – |
| POST | `/api/quiz/submit` | – |

Full reference: [docs/04_API_REFERENCE.md](docs/04_API_REFERENCE.md).

## Security notes
- Input validation, parameterised SQL, HTML escaping, rate limiting, role-checked write endpoints
- Demo keys are for local use only; change them via environment variables
- `/api/demo-keys` exists for the demo UI — remove it for any real deployment

## Testing
- 49 tests: validator, scoring, mapping, alerts, awareness, API, empty dataset
- Details: [reports/TEST_REPORT.md](reports/TEST_REPORT.md)

## Documentation and reports
| Folder | Files |
|---|---|
| [`docs/`](docs) | Overview, architecture, schema, API, scoring, concepts, user guide, security, testing, careers, interview Q&A |
| [`reports/`](reports) | `PROJECT_REPORT.md`, `TEST_REPORT.md`, `DATASET_REPORT.md`, `LINKEDIN_POST.md` |

## Limitations
- Synthetic data shows the workflow, not real-world accuracy
- Scoring weights are teaching defaults
- No automated browser tests; CDN needed for charts
- Not hardened for production

## Future work
- STIX/TAXII import, SIEM integration, IOC expiry
- PostgreSQL, Docker, real authentication
- React/Recharts front end

## Key principles
**High risk ≠ confirmed compromise · Correlation ≠ attribution · Alerts ≠ incidents**
