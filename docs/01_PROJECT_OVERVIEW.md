# 01 · Project Overview

## Problem
- Security teams receive thousands of indicators and alerts; analysts suffer from **alert fatigue**
- Many people lack basic security awareness, so phishing and weak passwords stay effective
- Students rarely get a safe, realistic environment to practise threat-intelligence workflows

## Goal
Build a **defensive** dashboard that turns synthetic threat data into prioritised, explainable insight and pairs it with an awareness programme.

## Objectives
- Collect, validate and normalise indicators of compromise (IOCs)
- Score **risk** and **confidence** separately and explain both
- Correlate repeated observations into fewer, better alerts
- Map threats to MITRE ATT&CK only when evidence supports it
- Prioritise vulnerabilities using context, not CVSS alone
- Teach security awareness through modules and a scored quiz

## Scope
| In scope | Out of scope |
|---|---|
| Synthetic data and reserved/example indicators | Real malware, exploits or live threat feeds |
| Database lookups of indicators | Scanning, probing or contacting indicators |
| Risk, confidence, alerting, awareness | Attribution of attacks to real actors |
| Local Flask + SQLite deployment | Production hardening, SSO, multi-tenant use |

## Feature summary
| Tab | Highlights |
|---|---|
| Overview | 8 KPIs, intelligence hierarchy, trend, severity, category, IOC and tactic charts, alerts, top indicators |
| Threat Intelligence | Filterable, sortable, paginated records; risk/confidence histograms; source reliability; campaigns |
| IOC Search | Validated lookup, sample indicators, safe-handling rules, highest-risk indicators |
| Alerts | Alert types/status charts, fatigue funnel, queue with status changes |
| Vulnerabilities | Severity/exposure/patch charts, fix-first list, priority formula, full table |
| ATT&CK | Tactic chart, technique list, tactic→technique matrix, mapping policy |
| Awareness | 15 modules, do/don't table, phishing red flags |
| Quiz | 40 questions, category scores, learning recommendations |
| About | Summary, stack, weights, ethics |

## Key principles
- **High risk ≠ confirmed compromise**
- **Correlation ≠ attribution**
- **Alerts ≠ incidents**
- Humans validate; the tool prioritises
