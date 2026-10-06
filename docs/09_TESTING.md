# 09 · Testing

## Strategy
| Level | Focus |
|---|---|
| Unit | Validator, scoring, mapping, alert rules, quiz scoring |
| API | Filters, sorting, search, auth, escaping, status updates |
| Edge cases | Empty dataset, invalid indicators, bad input |

## Run
```bash
python -m unittest discover -s tests -v
```
Tests use a temporary database and synthetic data only.

## Coverage by area
| Area | Tests |
|---|---|
| IOC validator | 13 |
| Scoring | 7 |
| ATT&CK mapping | 2 |
| Alerts | 4 |
| Awareness | 4 |
| API | 18 |
| Empty dataset | 1 |
| **Total** | **49** |

## Manual checklist
- [ ] Each of the 9 tabs opens and fills the page
- [ ] Charts render after switching tabs
- [ ] Threat filters and "Load more" work
- [ ] Sample indicators behave as expected
- [ ] Alert status dropdown saves
- [ ] Analyst note appears in the detail view
- [ ] Quiz completes and shows recommendations
- [ ] Layout works on a narrow window

## Not covered
- Automated browser/UI tests
- Load and penetration testing
