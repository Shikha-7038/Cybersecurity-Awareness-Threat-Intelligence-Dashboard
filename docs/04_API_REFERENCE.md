# 04 · API Reference

Base URL: `http://127.0.0.1:5000`. Responses are JSON. Write endpoints require header `X-API-Key`.

## Threats
| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/api/threats` | List/filter threats | – |
| GET | `/api/threats/{id}` | Detail, related indicators, alerts, notes, timeline | – |
| POST | `/api/threats/{id}/notes` | Add analyst note `{"note": "..."}` | analyst |

**`/api/threats` query parameters**
| Parameter | Meaning |
|---|---|
| severity, category, indicator_type, status | Exact filters (case-insensitive) |
| min_risk, min_confidence | Numeric minimums |
| q | Text search over indicator, name, id |
| sort | `newest` (default), `risk`, `confidence`, `observed` |
| limit, offset | Pagination (limit max 500) |

## Indicators, dashboard, alerts
| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/api/indicators/search?q=` | Validate + look up in the database only | – |
| GET | `/api/dashboard/stats` | KPIs, charts data, hierarchy, matrix, sources, campaigns | – |
| GET | `/api/alerts?status=` | Alert queue (max 200, highest risk first) | – |
| PUT | `/api/alerts/{id}/status` | Change status | analyst |

## Vulnerabilities and awareness
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/vulnerabilities` | All CVEs ordered by priority |
| GET | `/api/awareness/modules` | 15 learning modules |
| GET | `/api/quiz` | 40 questions (answers withheld) |
| POST | `/api/quiz/submit` | `{"answers": {"1": 2, ...}}` → score, level, recommendations, review |
| GET | `/api/demo-keys` | **Demo only** — returns the analyst key for the UI |

## Status codes
| Code | Meaning |
|---|---|
| 200 / 201 | Success / created |
| 400 | Invalid input (bad indicator, status, body) |
| 401 | Missing or unknown API key |
| 403 | Role not allowed |
| 404 | Threat or alert not found |
| 429 | Rate limit exceeded |

## Examples
```bash
curl "http://127.0.0.1:5000/api/threats?severity=high&sort=risk&limit=5"
curl "http://127.0.0.1:5000/api/indicators/search?q=198.51.100.25"
curl -X POST -H "X-API-Key: analyst-demo-key" -H "Content-Type: application/json" \
     -d '{"note":"Reviewed, monitoring"}' http://127.0.0.1:5000/api/threats/THR-2026-001/notes
```
