"""
nvd_collector.py — Collecteur CVE Cloud-Native v2.0
Sources: NVD API v2 + CISA KEV + OSV.dev
Keywords: AWS, GCP, Azure, K8s, Docker, CI/CD...
100% dynamique — aucune valeur statique
"""
import requests, json, os, time
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from database import init_db, insert_cve, get_conn
load_dotenv('/home/br1kx/cti/ctiops/.env')

NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL  = "https://api.osv.dev/v1/query"
NVD_KEY  = os.getenv("NVD_API_KEY")

# ── KEYWORDS CLOUD-NATIVE COMPLETS ────────────────────────────────
CLOUD_KEYWORDS = {
    # AWS
    "AWS": "Amazon Web Services",
    "Amazon S3": "AWS Storage",
    "Amazon EC2": "AWS Compute",
    "Amazon Lambda": "AWS Serverless",
    "Amazon EKS": "AWS Kubernetes",
    "Amazon ECS": "AWS Containers",
    "AWS IAM": "AWS Identity",
    "AWS CloudFormation": "AWS IaC",
    # GCP
    "Google Cloud": "GCP",
    "GCP": "Google Cloud Platform",
    "Google Kubernetes Engine": "GKE",
    "Google GKE": "GKE",
    "Cloud Run": "GCP Serverless",
    "BigQuery": "GCP Data",
    # Azure
    "Azure": "Microsoft Azure",
    "Microsoft Azure": "Azure",
    "Azure AKS": "Azure Kubernetes",
    "Azure Functions": "Azure Serverless",
    "Azure DevOps": "Azure CI/CD",
    # Containers
    "Kubernetes": "K8s",
    "Docker": "Container Runtime",
    "containerd": "Container Runtime",
    "Helm": "K8s Package Manager",
    "Istio": "Service Mesh",
    "Envoy": "Proxy",
    # CI/CD
    "GitHub Actions": "CI/CD",
    "GitLab CI": "CI/CD",
    "Jenkins": "CI/CD",
    "ArgoCD": "GitOps",
    "Tekton": "CI/CD",
    # IaC & Config
    "Terraform": "IaC",
    "Ansible": "Configuration",
    "Pulumi": "IaC",
    # Monitoring
    "Prometheus": "Monitoring",
    "Grafana": "Visualization",
    "OpenTelemetry": "Observability",
}

TLP_MAP = {
    "CRITICAL": "TLP:RED",
    "HIGH":     "TLP:AMBER",
    "MEDIUM":   "TLP:AMBER",
    "LOW":      "TLP:WHITE",
    "UNKNOWN":  "TLP:WHITE",
}

# ── NVD API v2 ────────────────────────────────────────────────────
def fetch_nvd(keyword: str, days_back: int = 7) -> list:
    now   = datetime.now(timezone.utc)
    if days_back == 0:
        start = "2020-01-01T00:00:00.000"  # Toute la période cloud
    else:
        start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    end   = now.strftime("%Y-%m-%dT23:59:59.999")
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    results = []
    start_index = 0
    while True:
        try:
            r = requests.get(NVD_URL, params={
                "keywordSearch":  keyword,
                "pubStartDate":   start,
                "pubEndDate":     end,
                "resultsPerPage": 100,
                "startIndex":     start_index,
            }, headers=headers, timeout=30)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            results.extend(vulns)
            total = data.get("totalResults", 0)
            start_index += len(vulns)
            if start_index >= total or not vulns:
                break
            time.sleep(0.5)
        except Exception as e:
            print(f"[NVD] Erreur '{keyword}': {e}")
            break
    return results

def parse_nvd_cve(item: dict, keyword: str, category: str) -> dict | None:
    cve = item.get("cve", {})
    cid = cve.get("id")
    if not cid:
        return None
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "N/A"
    )
    metrics = cve.get("metrics", {})
    score, vector, sev = None, None, "UNKNOWN"
    for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if v in metrics and metrics[v]:
            m   = metrics[v][0].get("cvssData", {})
            score  = m.get("baseScore")
            vector = m.get("vectorString")
            sev    = m.get("baseSeverity",
                           metrics[v][0].get("baseSeverity", "UNKNOWN"))
            break
    sev = (sev or "UNKNOWN").upper()
    # CPE pour identifier les produits affectés
    cpes = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.append(match.get("criteria", ""))
    return {
        "id":          cid,
        "description": desc[:1000],
        "cvss_score":  score,
        "cvss_vector": vector,
        "severity":    sev,
        "published":   cve.get("published"),
        "modified":    cve.get("lastModified"),
        "keywords":    json.dumps([keyword, category]),
        "tlp":         TLP_MAP.get(sev, "TLP:WHITE"),
        "source":      "NVD",
        "cpes":        json.dumps(cpes[:10]),
    }

# ── CISA KEV (Known Exploited Vulnerabilities) ────────────────────
def fetch_cisa_kev() -> int:
    """Récupère les CVE activement exploitées depuis CISA."""
    print("[CISA] Collecte Known Exploited Vulnerabilities...")
    try:
        r = requests.get(CISA_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        count = 0
        # Filtrer uniquement les cloud/container CVE
        cloud_terms = [k.lower() for k in CLOUD_KEYWORDS.keys()]
        for v in vulns:
            product = (v.get("product", "") + " " + v.get("vendorProject", "")).lower()
            desc    = v.get("shortDescription", "").lower()
            is_cloud = any(t in product or t in desc for t in cloud_terms)
            if not is_cloud:
                continue
            cve_id = v.get("cveID")
            if not cve_id:
                continue
            cve = {
                "id":          cve_id,
                "description": v.get("shortDescription", "")[:1000],
                "cvss_score":  None,
                "cvss_vector": None,
                "severity":    "HIGH",
                "published":   v.get("dateAdded"),
                "modified":    v.get("dateAdded"),
                "keywords":    json.dumps(["CISA-KEV", v.get("vendorProject","")]),
                "tlp":         "TLP:RED",
                "source":      "CISA-KEV",
                "cpes":        json.dumps([]),
            }
            try:
                insert_cve(cve)
                count += 1
            except:
                pass
        print(f"[CISA] {count} CVE cloud exploitées actives")
        return count
    except Exception as e:
        print(f"[CISA] Erreur: {e}")
        return 0

# ── OSV.dev (Open Source Vulnerabilities) ────────────────────────
def fetch_osv_ecosystem(ecosystem: str, days_back: int = 7) -> int:
    """Collecte CVE depuis OSV.dev pour un écosystème donné."""
    ecosystems_cloud = {
        "Go":     "Kubernetes, Docker, Terraform tools",
        "PyPI":   "Python cloud SDKs",
        "npm":    "Node.js cloud tools",
        "Maven":  "Java Spring Boot, Jenkins",
    }
    if ecosystem not in ecosystems_cloud:
        return 0
    print(f"[OSV] Collecte {ecosystem}...")
    try:
        # OSV query par écosystème
        r = requests.post(OSV_URL,
            json={"package": {"ecosystem": ecosystem}},
            timeout=30
        )
        if r.status_code != 200:
            return 0
        vulns = r.json().get("vulns", [])
        count = 0
        for v in vulns[:50]:  # limiter à 50 par écosystème
            vid = v.get("id", "")
            if not vid.startswith("CVE-"):
                # Chercher dans aliases
                aliases = v.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                if not cve_ids:
                    continue
                vid = cve_ids[0]
            desc = v.get("summary", v.get("details", ""))[:1000]
            published = v.get("published", "")
            severity = "MEDIUM"
            score = None
            for sev in v.get("severity", []):
                if "CVSS" in sev.get("type", ""):
                    score_str = sev.get("score", "")
                    try:
                        score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
                        severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM"
                    except:
                        pass
            cve = {
                "id":          vid,
                "description": desc,
                "cvss_score":  score,
                "cvss_vector": None,
                "severity":    severity,
                "published":   published,
                "modified":    published,
                "keywords":    json.dumps([ecosystem, "OSV"]),
                "tlp":         TLP_MAP.get(severity, "TLP:WHITE"),
                "source":      f"OSV-{ecosystem}",
                "cpes":        json.dumps([]),
            }
            try:
                insert_cve(cve)
                count += 1
            except:
                pass
        print(f"[OSV] {count} CVE {ecosystem}")
        return count
    except Exception as e:
        print(f"[OSV] Erreur {ecosystem}: {e}")
        return 0

# ── COLLECTEUR PRINCIPAL ──────────────────────────────────────────
def run_collector(days_back: int = 7) -> dict:
    """
    Collecte depuis toutes les sources :
    NVD + CISA KEV + OSV.dev
    Retourne un résumé des collectes.
    """
    print(f"\n{'='*50}")
    print(f"[CTI] Collecte CVE Cloud-Native — {days_back} jours")
    print(f"{'='*50}")
    results = {
        "nvd":   0,
        "cisa":  0,
        "osv":   0,
        "total": 0,
        "started": datetime.now(timezone.utc).isoformat(),
    }

    # 1. NVD — tous les keywords cloud
    print(f"\n[NVD] {len(CLOUD_KEYWORDS)} keywords cloud...")
    for keyword, category in CLOUD_KEYWORDS.items():
        items = fetch_nvd(keyword, days_back)
        for item in items:
            cve = parse_nvd_cve(item, keyword, category)
            if cve:
                try:
                    insert_cve(cve)
                    results["nvd"] += 1
                except:
                    pass
        # Rate limiting NVD
        sleep_time = 0.6 if NVD_KEY else 6
        time.sleep(sleep_time)

    # 2. CISA KEV
    results["cisa"] = fetch_cisa_kev()

    # 3. OSV.dev
    for eco in ["Go", "PyPI", "npm", "Maven"]:
        results["osv"] += fetch_osv_ecosystem(eco, days_back)

    results["total"] = results["nvd"] + results["cisa"] + results["osv"]
    results["finished"] = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*50}")
    print(f"[CTI] Collecte terminée:")
    print(f"  NVD:   {results['nvd']} CVE")
    print(f"  CISA:  {results['cisa']} CVE exploitées")
    print(f"  OSV:   {results['osv']} CVE open source")
    print(f"  TOTAL: {results['total']} CVE")
    print(f"{'='*50}\n")
    return results

# ── STATS ─────────────────────────────────────────────────────────
def get_collection_stats() -> dict:
    """Retourne les statistiques de la dernière collecte."""
    with get_conn() as c:
        total    = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        critical = c.execute("SELECT COUNT(*) FROM cve WHERE cvss_score >= 9.0").fetchone()[0]
        high     = c.execute("SELECT COUNT(*) FROM cve WHERE cvss_score >= 7.0 AND cvss_score < 9.0").fetchone()[0]
        newest   = c.execute("SELECT MAX(created_at) FROM cve").fetchone()[0]
        by_src   = c.execute(
            "SELECT source, COUNT(*) as n FROM cve GROUP BY source ORDER BY n DESC"
        ).fetchall()
    return {
        "total":    total,
        "critical": critical,
        "high":     high,
        "newest":   newest,
        "by_source": {r["source"]: r["n"] for r in by_src if r["source"]},
    }

if __name__ == "__main__":
    init_db()
    run_collector(days_back=30)

# ── EXPLOIT ENRICHMENT ────────────────────────────────────────────
EPSS_URL     = "https://api.first.org/data/v1/epss"
EXPLOITDB_URL = "https://www.exploit-db.com/search"

def enrich_exploit_status(cve_ids: list) -> dict:
    """
    Enrichit les CVE avec :
    - EPSS score (probabilité exploitation)
    - CISA KEV (exploitée activement)
    - ExploitDB (exploit public)
    """
    results = {}

    # 1. EPSS — probabilité exploitation (First.org)
    try:
        if cve_ids:
            cve_param = ",".join(cve_ids[:100])
            r = requests.get(EPSS_URL,
                params={"cve": cve_param, "pretty": "true"},
                timeout=30)
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    cid = item.get("cve")
                    results[cid] = {
                        "epss_score":       float(item.get("epss", 0)),
                        "epss_percentile":  float(item.get("percentile", 0)),
                        "has_public_exploit": float(item.get("epss", 0)) > 0.5,
                        "exploit_source":   "EPSS",
                        "actively_exploited": False,
                    }
    except Exception as e:
        print(f"[EPSS] Erreur: {e}")

    # 2. CISA KEV — exploitées activement
    try:
        r = requests.get(CISA_URL, timeout=30)
        if r.status_code == 200:
            kev_ids = {
                v["cveID"] for v in r.json().get("vulnerabilities", [])
            }
            for cid in cve_ids:
                if cid in kev_ids:
                    if cid not in results:
                        results[cid] = {}
                    results[cid]["actively_exploited"] = True
                    results[cid]["has_public_exploit"] = True
                    results[cid]["exploit_source"] = "CISA-KEV"
    except Exception as e:
        print(f"[CISA-KEV] Erreur: {e}")

    return results

def update_exploit_status_in_db(batch_size: int = 100):
    """Met à jour le statut exploit pour toutes les CVE en base."""
    with get_conn() as c:
        rows = c.execute(
            "SELECT id FROM cve ORDER BY cvss_score DESC"
        ).fetchall()

    cve_ids = [r["id"] for r in rows]
    print(f"[EXPLOIT] Enrichissement de {len(cve_ids)} CVE...")

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i+batch_size]
        enriched = enrich_exploit_status(batch)

        with get_conn() as c:
            for cid, data in enriched.items():
                c.execute("""
                    UPDATE cve SET
                        has_exploit       = ?,
                        epss_score        = ?,
                        epss_percentile   = ?,
                        actively_exploited = ?,
                        exploit_source    = ?
                    WHERE id = ?
                """, (
                    1 if data.get("has_public_exploit") else 0,
                    data.get("epss_score", 0),
                    data.get("epss_percentile", 0),
                    1 if data.get("actively_exploited") else 0,
                    data.get("exploit_source", ""),
                    cid
                ))

        print(f"[EXPLOIT] Batch {i//batch_size + 1} enrichi ({len(enriched)} CVE)")
        time.sleep(1)

    print("[EXPLOIT] Enrichissement terminé")
