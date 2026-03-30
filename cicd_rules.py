"""cicd_rules.py — Règles détection incidents CI/CD"""
import json, re
from datetime import datetime, timezone

MITRE_MAP = {
    "secret_exposed":    ("T1552.001", "Credentials In Files"),
    "image_unsigned":    ("T1195.002", "Compromise Software Supply Chain"),
    "job_failed_repeat": ("T1499",     "Endpoint Denial of Service"),
    "priv_escalation":   ("T1548",     "Abuse Elevation Control Mechanism"),
    "suspicious_push":   ("T1195",     "Supply Chain Compromise"),
    "workflow_injected": ("T1059",     "Command and Scripting Interpreter"),
    "unknown":           ("T1078",     "Valid Accounts"),
}
SECRET_PATTERNS = [
    r"(?i)(aws_secret_access_key|aws_access_key_id)\s*=\s*\S+",
    r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S{8,}",
    r"ghp_[a-zA-Z0-9]{36}",
    r"AKIA[0-9A-Z]{16}",
]
TLP_MAP = {"CRITICAL":"TLP:RED","HIGH":"TLP:AMBER","MEDIUM":"TLP:AMBER","LOW":"TLP:WHITE"}

def detect_event_type(payload: dict, event: str) -> str:
    if event == "secret_scanning_alert":
        return "secret_exposed"
    if event == "workflow_run":
        run = payload.get("workflow_run", {})
        if run.get("conclusion") == "failure":
            name = run.get("name", "").lower()
            return "suspicious_push" if any(k in name for k in ["deploy","push","release"]) else "job_failed_repeat"
    if event == "push":
        for commit in payload.get("commits", []):
            msg = commit.get("message", "")
            if any(re.search(p, msg) for p in SECRET_PATTERNS):
                return "secret_exposed"
            if any(k in msg.lower() for k in ["sudo","chmod 777","privilege"]):
                return "priv_escalation"
    return "unknown"

def get_severity(event_type: str) -> str:
    if event_type in ("secret_exposed", "workflow_injected"): return "CRITICAL"
    if event_type in ("priv_escalation", "image_unsigned"):   return "HIGH"
    if event_type == "suspicious_push":                        return "MEDIUM"
    return "LOW"

def extract_iocs(payload: dict) -> list:
    iocs = []
    raw  = json.dumps(payload)
    for ip in set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)):
        if not ip.startswith(("127.","10.","192.168.","172.")):
            iocs.append({"type":"ip","value":ip})
    for h in set(re.findall(r'\b[a-fA-F0-9]{64}\b', raw)):
        iocs.append({"type":"hash","value":h})
    return iocs[:5]

def analyze_event(payload: dict, event: str) -> dict | None:
    # Ignorer les workflow_run non terminés
    if event == "workflow_run":
        action = payload.get("action","")
        if action not in ("completed",):
            return None

    if event in ("ping","installation","check_run","check_suite",
                  "status","pull_request","create","delete",
                  "fork","watch","star","release"):
        return None
    event_type = detect_event_type(payload, event)
    severity   = get_severity(event_type)
    mitre_id, mitre_name = MITRE_MAP.get(event_type, MITRE_MAP["unknown"])
    return {
        "source":      "github_actions",
        "repo":        payload.get("repository",{}).get("full_name","unknown"),
        "actor":       payload.get("sender",{}).get("login","unknown"),
        "event_type":  event_type,
        "severity":    severity,
        "raw_payload": json.dumps(payload)[:2000],
        "mitre_id":    mitre_id,
        "mitre_name":  mitre_name,
        "tlp":         TLP_MAP[severity],
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "iocs":        extract_iocs(payload),
    }

# Patch: améliorer détection workflow_run failure
_orig_detect = detect_event_type
def detect_event_type(payload, event):
    if event == "workflow_run":
        run = payload.get("workflow_run", {})
        if run.get("conclusion") == "failure":
            name = run.get("name", "").lower()
            head_commit_msg = run.get("head_commit", {}).get("message", "").lower()
            if any(k in name + head_commit_msg for k in ["secret","leak","key","token","password"]):
                return "secret_exposed"
            if any(k in name for k in ["deploy","push","release","prod"]):
                return "suspicious_push"
            return "job_failed_repeat"
    return _orig_detect(payload, event)
