# Dataset Report

_Generated automatically from the database. All data is **synthetic / demo only**._

## 1. Overview

| Metric | Value |
|---|---|
| Threat records | 2202 |
| Unique indicators | 1759 |
| Campaign clusters | 141 |
| Total observations | 31655 |
| Alerts after correlation | 1368 |
| Synthetic CVEs | 60 |
| Average risk score | 51.2 |
| Average confidence | 55.2 |


## 2. Severity distribution

| Value | Records | Share |
|---|---|---|
| CRITICAL | 7 | 0.3% |
| HIGH | 448 | 20.3% |
| MEDIUM | 1347 | 61.2% |
| LOW | 398 | 18.1% |
| INFORMATIONAL | 2 | 0.1% |


## 3. Threat categories

| Value | Records | Share |
|---|---|---|
| WEB THREATS | 361 | 16.4% |
| PHISHING | 336 | 15.3% |
| NETWORK THREATS | 290 | 13.2% |
| CREDENTIAL THEFT | 251 | 11.4% |
| MALWARE | 246 | 11.2% |
| DATA EXPOSURE | 189 | 8.6% |
| VULNERABILITY EXPLOITATION | 184 | 8.4% |
| ACCOUNT TAKEOVER RISK | 156 | 7.1% |
| SOCIAL ENGINEERING | 102 | 4.6% |
| RANSOMWARE | 87 | 4.0% |


## 4. Indicator types

| Value | Records | Share |
|---|---|---|
| IP ADDRESS | 676 | 30.7% |
| DOMAIN | 573 | 26.0% |
| URL | 442 | 20.1% |
| EMAIL DOMAIN | 259 | 11.8% |
| FILE HASH | 167 | 7.6% |
| CVE ID | 85 | 3.9% |


## 5. Status workflow

| Value | Records | Share |
|---|---|---|
| NEW | 642 | 29.2% |
| MONITORING | 537 | 24.4% |
| UNDER REVIEW | 441 | 20.0% |
| CLOSED | 435 | 19.8% |
| FALSE POSITIVE | 147 | 6.7% |


## 6. Sources and reliability

| Value | Records | Share |
|---|---|---|
| Public Threat Feed (C) | 602 | 27.3% |
| Security Vendor (B) | 442 | 20.1% |
| Internal SOC (A) | 428 | 19.4% |
| Community Submission (D) | 278 | 12.6% |
| Research Report (B) | 264 | 12.0% |
| Unknown Source (D) | 188 | 8.5% |


## 7. Countries / regions

| Value | Records | Share |
|---|---|---|
| IN | 199 | 9.0% |
| AU | 196 | 8.9% |
| DE | 195 | 8.9% |
| JP | 188 | 8.5% |
| BR | 187 | 8.5% |
| ZA | 186 | 8.4% |
| GB | 180 | 8.2% |
| FR | 177 | 8.0% |
| CA | 177 | 8.0% |
| SG | 176 | 8.0% |
| US | 173 | 7.9% |
| NL | 168 | 7.6% |


## 8. ATT&CK coverage (only where confidence >= 50)

| Tactic | Technique | Records |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing Application | 333 |
| Initial Access | T1566 Phishing | 191 |
| Discovery | T1046 Network Service Discovery | 185 |
| Credential Access | T1555 Credentials from Password Stores | 163 |
| Exfiltration | T1567 Exfiltration Over Web Service | 137 |
| Initial Access | T1078 Valid Accounts | 101 |
| Execution | T1204 User Execution | 78 |
| Command and Control | T1071 Application Layer Protocol | 71 |
| Impact | T1486 Data Encrypted for Impact | 67 |
| Reconnaissance | T1598 Phishing for Information | 65 |


Unmapped records (insufficient evidence): **811**


## 9. Vulnerabilities

| Severity | CVEs | Avg CVSS | Avg priority |
|---|---|---|---|
| CRITICAL | 31 | 9.6 | 66.4 |
| HIGH | 18 | 8.1 | 62.9 |
| MEDIUM | 8 | 4.9 | 52.1 |
| LOW | 3 | 3.3 | 49.7 |


**Top 5 priorities**


| CVE | Product | CVSS | Exposure | Priority |
|---|---|---|---|---|
| CVE-2099-10054 | CMS Plugin | 8.7 | internet | 85 |
| CVE-2099-10008 | Office Suite | 9.7 | internet | 84 |
| CVE-2099-10047 | Web Server | 9.2 | internal | 84 |
| CVE-2099-10003 | Router Firmware | 9.8 | internal | 81 |
| CVE-2099-10046 | Database | 9.7 | internal | 81 |


## 10. Safety of the data

- IPs only from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737 documentation ranges)
- Domains only under `example.com`, `example.org`, `example.net`, `.invalid`
- File hashes are random strings; they match no real file
- CVE IDs use the unassigned `CVE-2099-*` range
- Every description is labelled `SYNTHETIC / DEMO ONLY`
