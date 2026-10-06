# 08 · Security & Ethics

## Safe-by-design rules
- Synthetic data only; all records labelled `SYNTHETIC / DEMO ONLY`
- Reserved IP ranges (RFC 5737), `example.*` and `.invalid` domains, `CVE-2099-*` IDs
- No scanning, exploitation, malware, credential harvesting or live probing
- Indicator search is a **database lookup**; nothing is contacted
- No exploit details in vulnerability records

## Application controls
| Control | Where | Protects against |
|---|---|---|
| Indicator validation | `ioc_validator.py` | Malformed or hostile input |
| Parameterised SQL | `app.py` | SQL injection |
| HTML escaping | `clean()` and UI `esc()` | Stored/reflected XSS |
| API key + role check | `require_role` | Unauthorised writes |
| Rate limiting | `before_request` | Abuse of the API |
| Input length limits | `clean()` | Oversized payloads |
| Server-side quiz scoring | `/api/quiz/submit` | Answer leakage |

## Known limitations
| Limitation | Production fix |
|---|---|
| Demo key endpoint | Remove; use real authentication |
| In-memory rate limiter | Use a shared limiter or gateway |
| Plain HTTP | Terminate TLS |
| No audit log | Add immutable logging |
| SQLite | Move to PostgreSQL |

## Ethical principles
- **Defend, don't attack**
- **Explain every score**, so analysts can challenge it
- **Respect uncertainty**: confidence is shown next to risk
- **Avoid attribution claims** from correlation alone
- **Quiz is educational**, not an assessment of a person

## Responsible use
- Do not replace the synthetic data with real intelligence without proper authorisation and handling rules
- Do not use the tool to target systems you do not own
