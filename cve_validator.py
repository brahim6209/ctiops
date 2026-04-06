"""cve_validator.py — CVE Validation + Relevance + Priority"""
import re
from database import get_conn

CLOUD_KEYWORDS = [
    "aws","azure","gcp","cloud","kubernetes","k8s","docker","container",
    "jenkins","github","gitlab","terraform","ansible","lambda","s3",
    "spring","tomcat","log4j","jackson","oauth","jwt"
]

def validate_cve_id(cve_id):
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve_id))

def check_relevance(cve_id):
    if not validate_cve_id(cve_id):
        return {"valid": False, "error": "Invalid CVE ID format"}
    with get_conn() as c:
        row = c.execute("SELECT * FROM cve WHERE id=?", (cve_id,)).fetchone()
    if not row:
        return {"valid": True, "in_db": False, "relevant": False}
    d = dict(row)
    desc = (d.get("description") or "").lower()
    relevant = any(kw in desc for kw in CLOUD_KEYWORDS)
    score = float(d.get("cvss_score") or 0)
    epss = float(d.get("epss_score") or 0)
    return {
        "valid": True, "in_db": True, "relevant": relevant,
        "cvss": score, "epss": epss,
        "has_exploit": bool(d.get("has_exploit")),
        "actively_exploited": bool(d.get("actively_exploited")),
        "severity": d.get("severity","UNKNOWN"),
        "cloud_keywords_found": [kw for kw in CLOUD_KEYWORDS if kw in desc]
    }

def calculate_priority(cve_id):
    rel = check_relevance(cve_id)
    if not rel.get("in_db"):
        return {"priority": "UNKNOWN", "score": 0}
    score = 0
    if rel.get("actively_exploited"): score += 40
    if rel.get("has_exploit"): score += 20
    epss = rel.get("epss", 0)
    score += int(epss * 30)
    cvss = rel.get("cvss", 0)
    score += int((cvss / 10) * 10)
    priority = "P0-IMMEDIATE" if score>=80 else "P1-URGENT" if score>=60 else "P2-PLANNED" if score>=30 else "P3-MONITOR"
    return {"priority": priority, "score": score, "breakdown": rel}
