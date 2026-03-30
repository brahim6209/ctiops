"""virustotal.py — Enrichissement IOC via VirusTotal API v3"""
import requests, os, json, time, random
from dotenv import load_dotenv
from database import insert_enrichment, insert_recommendation

load_dotenv()
VT_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

def _headers():
    return {"x-apikey": VT_KEY} if VT_KEY else {}

def _fetch(url):
    try:
        r = requests.get(url, headers=_headers(), timeout=15)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        print(f"[VT] Erreur: {e}")
        return None

def enrich_ioc(value: str, ioc_type: str) -> dict:
    if not VT_KEY:
        return _mock(value, ioc_type)

    endpoints = {
        "ip":     f"{VT_BASE}/ip_addresses/{value}",
        "hash":   f"{VT_BASE}/files/{value}",
        "domain": f"{VT_BASE}/domains/{value}",
        "url":    f"{VT_BASE}/urls/{value}",
    }
    url  = endpoints.get(ioc_type)
    data = _fetch(url) if url else None

    if not data:
        return _mock(value, ioc_type)

    stats     = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    malicious = stats.get("malicious", 0)
    total     = sum(stats.values()) if stats else 1
    score     = round((malicious / total) * 100, 1)
    tags      = data.get("data",{}).get("attributes",{}).get("tags",[])

    result = {
        "ioc_value": value, "provider": "virustotal",
        "score": score, "malicious_count": malicious,
        "total_engines": total, "tags": json.dumps(tags),
    }
    insert_enrichment(result)

    if score > 70:
        insert_recommendation({
            "ref_id": value, "ref_type": "ioc", "priority": "critical",
            "title": f"IOC malveillant détecté : {value}",
            "description": f"Score VT: {score}% — {malicious}/{total} moteurs",
            "mitre_id": "T1078",
        })
    time.sleep(15)
    return result

def _mock(value: str, ioc_type: str) -> dict:
    score = random.randint(0, 100)
    result = {
        "ioc_value": value, "provider": "virustotal_mock",
        "score": score, "malicious_count": int(score * 0.7),
        "total_engines": 70, "tags": json.dumps(["mock"]),
    }
    insert_enrichment(result)
    return result
