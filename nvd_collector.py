"""nvd_collector.py — Collecte CVE cloud via NVD API v2"""
import requests, json, os, time
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from database import init_db, insert_cve

load_dotenv()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = os.getenv("NVD_API_KEY")

CLOUD_KEYWORDS = [
    "AWS", "Azure", "GCP", "Google Cloud",
    "Kubernetes", "Docker", "container",
    "serverless", "IAM", "S3", "Lambda",
    "GitHub Actions", "GitLab", "CI/CD",
]
TLP_MAP = {"CRITICAL":"TLP:RED","HIGH":"TLP:AMBER","MEDIUM":"TLP:AMBER","LOW":"TLP:WHITE"}

def fetch_cves(keyword: str, days_back: int = 7) -> list:
    now   = datetime.now(timezone.utc)
    start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    end   = now.strftime("%Y-%m-%dT23:59:59.999")
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    try:
        r = requests.get(NVD_URL, params={
            "keywordSearch": keyword, "pubStartDate": start,
            "pubEndDate": end, "resultsPerPage": 50,
        }, headers=headers, timeout=30)
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])
    except Exception as e:
        print(f"[NVD] Erreur '{keyword}': {e}")
        return []

def parse_cve(item: dict, keyword: str) -> dict | None:
    cve = item.get("cve", {})
    cid = cve.get("id")
    if not cid:
        return None
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "N/A")
    metrics = cve.get("metrics", {})
    score, vector, sev = None, None, "UNKNOWN"
    for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if v in metrics and metrics[v]:
            m = metrics[v][0].get("cvssData", {})
            score  = m.get("baseScore")
            vector = m.get("vectorString")
            sev    = m.get("baseSeverity", metrics[v][0].get("baseSeverity", "UNKNOWN"))
            break
    sev = (sev or "UNKNOWN").upper()
    return {
        "id": cid, "description": desc[:1000],
        "cvss_score": score, "cvss_vector": vector,
        "severity": sev, "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "keywords": json.dumps([keyword]),
        "tlp": TLP_MAP.get(sev, "TLP:WHITE"),
    }

def run_collector(days_back: int = 7) -> int:
    print(f"[NVD] Collecte CVE cloud (derniers {days_back} jours)...")
    total = 0
    for kw in CLOUD_KEYWORDS:
        print(f"[NVD] Recherche: {kw}")
        for item in fetch_cves(kw, days_back):
            cve = parse_cve(item, kw)
            if cve:
                try:
                    insert_cve(cve)
                    total += 1
                except Exception as e:
                    print(f"[NVD] Erreur: {e}")
        time.sleep(1 if NVD_KEY else 6)
    print(f"[NVD] {total} CVE stockées.")
    return total

if __name__ == "__main__":
    init_db()
    run_collector(days_back=30)
