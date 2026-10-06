# 07 · User Guide

## Start
1. Follow the steps in the main `README.md`
2. Open `http://127.0.0.1:5000`
3. Use the tab bar; the address bar remembers the tab (e.g. `#alerts`)

## Tabs
| Tab | What you can do |
|---|---|
| Overview | Read KPIs and the hierarchy; scan trend, severity, categories; click a threat row for details |
| Threat Intelligence | Filter by severity, category, status; sort; load more; review sources and campaigns |
| IOC Search | Paste an indicator; use sample buttons; open the linked investigation |
| Alerts | Filter the queue; change an alert's status with the dropdown |
| Vulnerabilities | See fix-first CVEs, charts, and the full priority table |
| ATT&CK | Browse tactics, techniques and the mapping policy |
| Awareness | Read the 15 modules, do/don't table and red flags |
| Quiz | Answer 40 questions; read scores and recommendations |
| About | Review stack, weights and ethics |

## Typical analyst workflow
1. Overview → spot the highest-risk threats
2. Threat Intelligence → filter `HIGH` + `NEW`
3. Open a record → read timeline, related indicators, ATT&CK
4. Add an analyst note
5. Alerts → set status to Investigating, Monitoring or False positive
6. Vulnerabilities → check whether a related CVE is patched

## Try these indicators
| Indicator | Expected result |
|---|---|
| `198.51.100.25` | Known, risk 78, phishing infrastructure |
| `login-check.invalid` | Known, risk 78, demo phishing domain |
| `CVE-2099-10001` | Valid CVE format; lookup result depends on dataset |
| `999.1.1.1` | Rejected as invalid |
| `example.org` | Valid, not in the dataset |

## Troubleshooting
| Symptom | Fix |
|---|---|
| Blank charts | Check internet access (Chart.js loads from a CDN) |
| Port 5000 busy | Change the port in the last line of `backend/app.py` |
| Empty dashboard | Run `python data/generate_threat_data.py`, delete `threat_intel.db`, restart |
| 401 on notes/status | Keep the demo key route enabled locally |
