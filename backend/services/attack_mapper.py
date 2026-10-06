"""Conservative MITRE ATT&CK mapping. Only maps when there is enough context; an IOC alone never proves a technique.
Technique IDs are well-known ones - verify at https://attack.mitre.org before publishing."""
MAP = {
    "PHISHING": ("Initial Access", "Phishing", "T1566"),
    "MALWARE": ("Execution", "User Execution", "T1204"),
    "RANSOMWARE": ("Impact", "Data Encrypted for Impact", "T1486"),
    "CREDENTIAL_THEFT": ("Credential Access", "Credentials from Password Stores", "T1555"),
    "SOCIAL_ENGINEERING": ("Reconnaissance", "Phishing for Information", "T1598"),
    "NETWORK_THREATS": ("Discovery", "Network Service Discovery", "T1046"),
    "WEB_THREATS": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "DATA_EXPOSURE": ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
    "ACCOUNT_TAKEOVER_RISK": ("Initial Access", "Valid Accounts", "T1078"),
    "VULNERABILITY_EXPLOITATION": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
}


def map_threat(category, indicator_type, confidence):
    """Return {tactic, technique, technique_id} or None when evidence is insufficient (confidence < 50)."""
    if confidence < 50 or category not in MAP:
        return None
    tactic, tech, tid = MAP[category]
    if category == "MALWARE" and indicator_type in ("DOMAIN", "IP_ADDRESS"):
        tactic, tech, tid = "Command and Control", "Application Layer Protocol", "T1071"
    return {"tactic": tactic, "technique": tech, "technique_id": tid}
