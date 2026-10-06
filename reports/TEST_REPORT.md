# Test Report

## Summary
| Item | Value |
|---|---|
| Framework | Python `unittest` |
| Command | `python -m unittest discover -s tests -v` |
| Tests | 49 |
| Result | All passing at the time of packaging |
| Data | Temporary SQLite database, synthetic data only |

## Results by area
| Area | Tests | What is checked |
|---|---|---|
| IOC validator | 13 | IPv4/IPv6, domain, URL, hashes, CVE, email domain, empty/invalid input |
| Scoring | 7 | Range, monotonic severity, recency decay, labels, confidence, CVE context |
| ATT&CK mapping | 2 | Mapping with evidence; no mapping at low confidence |
| Alerts | 4 | Rule triggers, low-confidence flag, no alert for low risk, correlation (50 → 1) |
| Awareness | 4 | Quiz scoring, levels, recommendations, empty quiz |
| API | 18 | Load, stats, filters, sorting, search, demo scenario, 404, auth, XSS escaping, status update, quiz |
| Empty dataset | 1 | Dashboard stats with zero records |
| **Total** | **49** | |

## Security-focused cases
| Case | Expected |
|---|---|
| Add note without API key | 401 |
| Note containing `<script>` | Stored escaped |
| Invalid alert status | 400 |
| Invalid indicator search | 400 |
| Quiz response | Never includes correct answers before submission |

## Not tested automatically
- Browser rendering and chart visuals
- Responsive layout
- Performance under load
- Penetration testing

Use the manual checklist in `docs/09_TESTING.md` for these.
