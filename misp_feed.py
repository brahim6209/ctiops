"""
misp_feed.py — Récupération feeds MISP
Structure réelle: EventTag[].Tag.name pour /events/index
"""
import os, re, requests
from dotenv import load_dotenv
load_dotenv('/home/br1kx/cti/ctiops/.env')

MISP_URL = os.getenv("MISP_URL", "https://localhost")
MISP_KEY = os.getenv("MISP_KEY", "")
HEADERS  = {"Authorization": MISP_KEY, "Accept": "application/json",
            "Content-Type": "application/json"}

def _get_tags(event: dict) -> list:
    """Extraire les noms de tags depuis la structure MISP réelle."""
    tags = []
    # /events/index retourne EventTag[].Tag.name
    for et in event.get("EventTag", []):
        name = et.get("Tag", {}).get("name", "")
        if name:
            tags.append(name.lower())
    # /events/:id retourne Tag[].name directement
    for t in event.get("Tag", []):
        name = t.get("name", "") if isinstance(t, dict) else str(t)
        if name and name.lower() not in tags:
            tags.append(name.lower())
    return tags

def get_misp_intelligence(limit: int = 500) -> dict:
    """Récupérer et structurer tous les events MISP."""
    try:
        r = requests.get(
            f"{MISP_URL}/events/index",
            headers=HEADERS, verify=False, timeout=20
        )
        if r.status_code != 200:
            return _empty_response(f"HTTP {r.status_code}")
        events = r.json()
    except Exception as e:
        return _empty_response(str(e))

    cve_events      = []
    incident_events = []
    ioc_events      = []
    mitre_map       = {}
    tlp_dist        = {}
    tag_counts      = {}
    threat_levels   = {"1": 0, "2": 0, "3": 0, "4": 0}

    for e in events[:limit]:
        tags = _get_tags(e)

        # Comptages
        for tag in tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            if tag.startswith("tlp:"):
                tlp_dist[tag] = tlp_dist.get(tag, 0) + 1
            if tag.startswith("mitre-attack:") or tag.startswith("mitre:"):
                tech = tag.split(":")[-1].strip().upper()
                mitre_map[tech] = mitre_map.get(tech, 0) + 1

        tl = str(e.get("threat_level_id", "4"))
        threat_levels[tl] = threat_levels.get(tl, 0) + 1

        info = e.get("info", "")
        obj  = {
            "id":           e.get("id"),
            "info":         info[:80],
            "date":         e.get("date", ""),
            "attr_count":   int(e.get("attribute_count", 0)),
            "threat_level": tl,
            "tags":         tags[:8],
            "tlp":          next((t for t in tags if t.startswith("tlp:")), "tlp:white"),
            "distribution": e.get("distribution", "0"),
        }

        info_l = info.lower()
        # CVE events
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', info, re.IGNORECASE)
        if cve_match or any(k in info_l for k in ["vulnerability", "exploit", "cve"]):
            obj["cve_id"]      = cve_match.group(0) if cve_match else ""
            obj["attack_type"] = _classify_attack(info_l)
            cve_events.append(obj)
        # Incident events
        elif any(k in info_l for k in ["incident", "pipeline", "secret", "scan",
                                        "jenkins", "trivy", "gitleaks", "ci/cd"]):
            obj["event_type"] = _classify_incident(info_l)
            incident_events.append(obj)
        # IOC events
        elif any(k in info_l for k in ["ioc", "malware", "c2", "botnet",
                                        "phishing", "hash", "ip block"]):
            obj["ioc_type"] = _classify_ioc(info_l)
            ioc_events.append(obj)
        else:
            # Classer selon tags
            if any(t in tags for t in ["cloud-security", "cve", "vulnerability"]):
                obj["attack_type"] = _classify_attack(info_l)
                cve_events.append(obj)
            else:
                obj["event_type"] = "OTHER"
                incident_events.append(obj)

    top_mitre = sorted(mitre_map.items(), key=lambda x: x[1], reverse=True)[:10]
    top_tags  = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    total     = len(events)

    return {
        "total_events":    total,
        "cve_events":      cve_events[:100],
        "incident_events": incident_events[:100],
        "ioc_events":      ioc_events[:50],
        "mitre_techniques":[{"technique": k, "count": v,
                             "label": _mitre_label(k)} for k, v in top_mitre],
        "tlp_distribution": tlp_dist,
        "top_tags":        [{"tag": k, "count": v} for k, v in top_tags],
        "threat_levels":   threat_levels,
        "summary": {
            "total_events":    total,
            "cve_events":      len(cve_events),
            "incident_events": len(incident_events),
            "ioc_events":      len(ioc_events),
            "critical_events": threat_levels.get("1", 0),
            "high_events":     threat_levels.get("2", 0),
            "tlp_red_count":   tlp_dist.get("tlp:red",   0),
            "tlp_amber_count": tlp_dist.get("tlp:amber", 0),
            "tlp_white_count": tlp_dist.get("tlp:white", 0),
            "top_mitre":       top_mitre[0][0] if top_mitre else "",
            "mitre_count":     len(mitre_map),
        }
    }

def _classify_attack(info: str) -> str:
    if any(k in info for k in ["rce","remote code","code execution"]): return "RCE"
    if any(k in info for k in ["privilege","escalation","privesc"]):   return "PRIVESC"
    if any(k in info for k in ["ssrf","server-side request"]):         return "SSRF"
    if any(k in info for k in ["sql injection"]):                      return "SQLI"
    if any(k in info for k in ["auth bypass","unauthenticated"]):      return "AUTH_BYPASS"
    if any(k in info for k in ["container","docker","kubernetes"]):    return "CONTAINER_ESCAPE"
    if any(k in info for k in ["supply chain","dependency"]):          return "SUPPLY_CHAIN"
    if any(k in info for k in ["disclosure","exposure","leak"]):       return "INFO_DISCLOSURE"
    return "UNKNOWN"

def _classify_incident(info: str) -> str:
    if "secret" in info or "gitleaks" in info: return "SECRET_LEAK"
    if "trivy" in info or "cve" in info:       return "CVE_SCAN"
    if "jenkins" in info or "pipeline" in info: return "PIPELINE"
    return "INCIDENT"

def _classify_ioc(info: str) -> str:
    if "hash" in info or "malware" in info: return "HASH"
    if "c2" in info or "botnet" in info:    return "C2_IP"
    if "phishing" in info:                  return "PHISHING_URL"
    return "IOC"

MITRE_LABELS = {
    "T1068": "Privilege Escalation", "T1190": "Exploit Public App",
    "T1195": "Supply Chain",         "T1552": "Unsecured Credentials",
    "T1078": "Valid Accounts",       "T1059": "Command Scripting",
    "T1499": "Denial of Service",    "T1611": "Container Escape",
    "T1083": "File Discovery",
}
def _mitre_label(tech: str) -> str:
    return MITRE_LABELS.get(tech, tech)

def _empty_response(error: str) -> dict:
    empty = {"total_events":0,"cve_events":[],"incident_events":[],"ioc_events":[],
             "mitre_techniques":[],"tlp_distribution":{},"top_tags":[],"threat_levels":{},
             "summary":{"total_events":0,"cve_events":0,"incident_events":0,"ioc_events":0,
                        "critical_events":0,"tlp_red_count":0,"tlp_amber_count":0,
                        "mitre_count":0,"top_mitre":"","error":error}}
    return empty

if __name__ == "__main__":
    d = get_misp_intelligence()
    s = d["summary"]
    print(f"Total events:    {s['total_events']}")
    print(f"CVE events:      {s['cve_events']}")
    print(f"Incident events: {s['incident_events']}")
    print(f"Critical (L1):   {s['critical_events']}")
    print(f"TLP:RED:         {s['tlp_red_count']}")
    print(f"TLP:AMBER:       {s['tlp_amber_count']}")
    print(f"MITRE count:     {s['mitre_count']}")
    print(f"\nTLP distribution: {d['tlp_distribution']}")
    print(f"\nTop tags:")
    for t in d['top_tags'][:8]: print(f"  {t['tag']:30} {t['count']}")
    print(f"\nMITRE techniques:")
    for t in d['mitre_techniques']: print(f"  {t['technique']} — {t['label']} ({t['count']}x)")
    print(f"\nSample CVE events:")
    for e in d['cve_events'][:3]:
        print(f"  [{e['tlp']}] {e.get('cve_id','')} | {e.get('attack_type','')} | {e['info'][:50]}")
