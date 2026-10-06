# 11 · Interview Q&A

| Question | Short answer |
|---|---|
| What does the project do? | A defensive dashboard that scores, correlates and visualises synthetic threat intelligence and teaches security awareness. |
| Why synthetic data? | It is safe, shareable and reproducible; no real threats or personal data. |
| Risk vs confidence? | Risk is potential impact; confidence is trust in the evidence. Both are shown. |
| Does high risk mean compromise? | No. It means "investigate first", and a human validates. |
| How do you reduce alert fatigue? | Rules filter alerts; correlation merges repeats into one alert with an observation count. |
| Why not rely on CVSS alone? | Asset criticality, exposure and exploitation change real priority. |
| How is ATT&CK mapping kept honest? | It maps only at confidence ≥ 50 and leaves other records unmapped. |
| How is the app secured? | Validation, parameterised SQL, HTML escaping, API keys, rate limiting. |
| What does the IOC search do? | A database lookup only; it never contacts the indicator. |
| How did you test it? | 49 unit and API tests, including empty-dataset and XSS cases. |
| Biggest limitation? | Synthetic data and teaching weights; not tuned on real incidents. |
| What would you add next? | STIX/TAXII ingestion, SIEM integration, IOC expiry, PostgreSQL, Docker, real authentication. |

## Talking points
- Show the Overview tab, then drill into one threat
- Explain one score end to end using `docs/05_SCORING_METHODOLOGY.md`
- Mention ethics up front: defensive, synthetic, no scanning
