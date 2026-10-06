# 06 · Threat Intelligence Concepts

## Intelligence hierarchy used in the dashboard
| Level | Meaning | Example |
|---|---|---|
| Observation | A single sighting of an artifact | A log line mentioning a domain |
| Indicator (IOC) | Data that may signal malicious activity | `login-check.invalid` |
| Alert | A prompt to investigate | "High risk, high confidence" |
| Threat | A campaign-level cluster | Synthetic phishing campaign |
| Incident | Confirmed security event needing response | Critical alert under investigation |

## Indicator of Compromise (IOC) types
| Type | Description | Handling rule |
|---|---|---|
| IP address | Network address | Never scan or connect |
| Domain | Hostname | Never browse |
| URL | Full web address | Never open |
| File hash | MD5 / SHA1 / SHA256 fingerprint | Never run a file because of a hash |
| Email domain | Sender domain | Do not reply |
| CVE ID | Vulnerability identifier | Check patch status |

## IOC lifecycle
1. **Collect** — from internal logs, vendors, reports, feeds
2. **Validate** — check syntax, remove duplicates
3. **Enrich** — add source, confidence, context
4. **Score** — risk and confidence
5. **Correlate** — group related sightings
6. **Act** — monitor, investigate, block through approved controls
7. **Review and expire** — indicators go stale; remove or lower them

## Types of threat intelligence
| Type | Audience | Question answered |
|---|---|---|
| Strategic | Executives | What risks matter to the organisation? |
| Operational | Defenders | What campaigns are active? |
| Tactical | SOC analysts | What behaviours and techniques are used? |
| Technical | Tools / SIEM | Which IOCs should we match? |

## MITRE ATT&CK
- A public knowledge base of adversary **tactics** (goals) and **techniques** (methods)
- Used here to organise detection and awareness work
- Mapping is conservative: low-confidence records stay unmapped
- Verify technique IDs at `attack.mitre.org`

## CVE, CVSS and prioritisation
| Term | Meaning |
|---|---|
| CVE | Public identifier for a vulnerability |
| CVSS | Standard 0–10 severity score |
| Asset criticality | How important the affected system is |
| Exposure | Internet-facing, internal or isolated |

CVSS alone is not enough; context decides what to fix first.

## Common mistakes
- Treating a high score as proof of compromise
- Blocking indicators without checking confidence
- Assuming shared infrastructure means the same actor
- Keeping indicators forever
- Ignoring false positives in the workflow
