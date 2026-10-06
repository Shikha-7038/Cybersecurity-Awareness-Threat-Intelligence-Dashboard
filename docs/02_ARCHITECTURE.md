# 02 · Architecture

## Components
| Layer | Technology | Responsibility |
|---|---|---|
| Presentation | HTML, CSS, JavaScript, Chart.js | Tabbed single-page UI, charts, forms |
| API | Flask (Python) | REST endpoints, validation, auth, rate limiting |
| Services | Python modules in `backend/services/` | Validation, scoring, ATT&CK mapping, alerts, quiz |
| Storage | SQLite | Threats, alerts, notes, vulnerabilities, quiz results |
| Data | CSV + generator script | Synthetic, safe demo data |

## Data pipeline
1. `data/generate_threat_data.py` writes synthetic CSVs
2. On first start, `init_db()` reads each row
3. **Validate** the indicator (`ioc_validator`) — invalid rows are rejected
4. **Normalise** (lower-case domains, canonical IPs, upper-case CVEs)
5. **Store** in SQLite
6. **Generate alerts** by rule (`alert_engine`)
7. **Correlate** duplicates into one alert with an observation count
8. API serves aggregates; UI renders them

## Folder map
```
Cybersecurity-Threat-Intelligence-Dashboard/
├── backend/            Flask app + services/
├── frontend/           index.html (tabbed UI)
├── data/               generator + generated CSVs
├── awareness/          modules.json, quiz_questions.json
├── tests/              test_all.py (49 tests)
├── docs/               this documentation
├── reports/            project, test and dataset reports
├── requirements.txt    dependencies
├── .env.example        configuration template
└── README.md
```

## Service modules
| Module | Purpose |
|---|---|
| `ioc_validator.py` | Syntax validation and normalisation (never network) |
| `risk_engine.py` | Risk, confidence, severity labels, CVE priority |
| `attack_mapper.py` | Conservative ATT&CK mapping |
| `alert_engine.py` | Rule-based alerts and time-window correlation |
| `awareness.py` | Quiz scoring, levels, recommendations |

## Design decisions
- **Flask + SQLite** keeps setup to two commands for students
- **Single HTML file** avoids a build step; tabs render lazily on first visit
- **Server-side quiz scoring** keeps answers out of the browser
- **Separate scoring modules** make each rule testable
