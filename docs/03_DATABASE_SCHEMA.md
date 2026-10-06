# 03 · Database Schema (SQLite)

## `threats`
| Column | Type | Notes |
|---|---|---|
| threat_id | TEXT PK | e.g. `THR-2026-001` |
| timestamp, first_seen, last_seen | TEXT | ISO-8601 |
| threat_name, category, description | TEXT | Synthetic labels |
| indicator_type, indicator_value | TEXT | Normalised by the validator |
| source_name, source_reliability | TEXT | Reliability A–D |
| confidence_score, risk_score | INT | 0–100 |
| severity, status | TEXT | See enums below |
| country | TEXT | Region code |
| tactic, technique, technique_id | TEXT | Empty when evidence is insufficient |
| cve_id | TEXT | Only for vulnerability-related records |
| campaign_id | TEXT | Synthetic cluster |
| observation_count | INT | Times seen |

Indexes: `indicator_value`, `severity`, `category`, `campaign_id`.

## `alerts`
| Column | Type |
|---|---|
| alert_id | INTEGER PK AUTOINCREMENT |
| threat_id, indicator_value | TEXT |
| timestamp, alert_type, severity, description, status | TEXT |
| risk_score, confidence_score, observation_count | INT |

## `vulnerabilities`
| Column | Type | Notes |
|---|---|---|
| cve_id | TEXT PK | `CVE-2099-*` (unassigned range) |
| product_category, severity, published_date | TEXT | |
| cvss_score | REAL | |
| patch_available, asset_criticality, priority_score | INT | Criticality 1–5 |
| exposure | TEXT | internet / internal / isolated |
| exploitation_status_demo | TEXT | none_observed / poc_discussed / exploited_in_demo |

## `notes`
`note_id` (PK), `threat_id`, `note` (HTML-escaped), `created_at`.

## `quiz_results`
`result_id` (PK), `overall_score`, `created_at` — no personal data stored.

## Enumerations
| Field | Values |
|---|---|
| severity | INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL |
| threat status | NEW, UNDER_REVIEW, MONITORING, CLOSED, FALSE_POSITIVE |
| alert status | NEW, INVESTIGATING, MONITORING, RESOLVED, FALSE_POSITIVE |
| indicator_type | IP_ADDRESS, DOMAIN, URL, FILE_HASH, EMAIL_DOMAIN, CVE_ID |
