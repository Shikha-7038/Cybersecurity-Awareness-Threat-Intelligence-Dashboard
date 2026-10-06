"""IOC validation: checks SYNTAX only ("is this well-formed?"), never "is this malicious?"."""
import re, ipaddress
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
HASH_TYPES = {32: "MD5", 40: "SHA1", 64: "SHA256"}


def validate_indicator(value):
    """Return dict(valid, indicator_type, normalized_value, validation_notes). Never connects anywhere."""
    v = (value or "").strip()
    res = {"valid": False, "indicator_type": None, "normalized_value": v,
           "validation_notes": "Syntax check only - says nothing about whether it is malicious."}
    if not v:
        res["validation_notes"] = "Empty value."
        return res
    if CVE_RE.match(v.upper()):
        return {**res, "valid": True, "indicator_type": "CVE_ID", "normalized_value": v.upper()}
    if v.lower().startswith(("http://", "https://")):
        host = (urlparse(v).hostname or "").lower()
        if DOMAIN_RE.match(host) or _is_ip(host):
            return {**res, "valid": True, "indicator_type": "URL", "normalized_value": v}
        res["validation_notes"] = "URL host is not a valid domain or IP."
        return res
    if _is_ip(v):
        return {**res, "valid": True, "indicator_type": "IP_ADDRESS", "normalized_value": str(ipaddress.ip_address(v))}
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HASH_TYPES:
        return {**res, "valid": True, "indicator_type": "FILE_HASH", "normalized_value": v.lower(),
                "validation_notes": f"{HASH_TYPES[len(v)]}-format hash (syntax only). Never execute files based on hashes."}
    if "@" in v and DOMAIN_RE.match(v.rsplit("@", 1)[1].lower()):
        return {**res, "valid": True, "indicator_type": "EMAIL_DOMAIN", "normalized_value": v.lower()}
    if DOMAIN_RE.match(v.lower()):
        return {**res, "valid": True, "indicator_type": "DOMAIN", "normalized_value": v.lower()}
    res["validation_notes"] = "Unrecognized or malformed indicator."
    return res


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
