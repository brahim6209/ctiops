"""
ioc_collector.py — Collecteur IOC dynamique multi-sources
Sources : GitHub Secret Scanning + Abuse.ch + AlienVault OTX + AWS GuardDuty
"""
import requests, os, json, time
from datetime import datetime, timezone
from dotenv import load_dotenv
from database import init_db, insert_ioc, insert_enrichment, insert_recommendation, get_conn

load_dotenv()

GITHUB_TOKEN  = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO   = os.getenv("GITHUB_REPO", "")        # ex: brahim6209/cti-test-pipeline
OTX_API_KEY   = os.getenv("OTX_API_KEY", "")
AWS_ACCESS_KEY= os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY= os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION    = os.getenv("AWS_REGION", "us-east-1")

TLP_MAP = {"CRITICAL":"TLP:RED","HIGH":"TLP:AMBER","MEDIUM":"TLP:AMBER","LOW":"TLP:WHITE"}

# ─────────────────────────────────────────────────────────────
# SOURCE 1 — GitHub Secret Scanning API
# ─────────────────────────────────────────────────────────────

def collect_github_secrets() -> int:
    """Collecte les alertes Secret Scanning depuis un repo GitHub."""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        print("[GitHub] Token ou repo non configuré — simulation")
        return _mock_github_secrets()

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    url = f"https://api.github.com/repos/{GITHUB_REPO}/secret-scanning/alerts"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            print("[GitHub] Secret Scanning non activé sur ce repo")
            return _mock_github_secrets()
        r.raise_for_status()
        alerts = r.json()
        count = 0
        for alert in alerts:
            secret_type = alert.get("secret_type_display_name", "unknown")
            secret_val  = alert.get("secret", "REDACTED")[:50]
            location    = alert.get("html_url", "")
            ioc = {
                "type":   "secret",
                "value":  f"github_secret:{alert.get('number',0)}:{secret_type}",
                "source": f"github_secret_scanning:{GITHUB_REPO}",
                "tlp":    "TLP:RED",
            }
            insert_ioc(ioc)
            insert_recommendation({
                "ref_id":      f"github_secret_{alert.get('number',0)}",
                "ref_type":    "ioc",
                "priority":    "critical",
                "title":       f"Secret exposé : {secret_type}",
                "description": f"Secret détecté dans {GITHUB_REPO}. Révoquer immédiatement.",
                "mitre_id":    "T1552.001",
            })
            count += 1
        print(f"[GitHub] {count} secrets collectés")
        return count
    except Exception as e:
        print(f"[GitHub] Erreur: {e}")
        return _mock_github_secrets()


def _mock_github_secrets() -> int:
    """Simule des alertes GitHub Secret Scanning."""
    mocks = [
        {"type":"ip", "value":"192.30.255.112", "source":"github_secret_scanning", "tlp":"TLP:AMBER"},
        {"type":"domain", "value":"raw.githubusercontent.com.evil.io", "source":"github_secret_scanning", "tlp":"TLP:RED"},
        {"type":"hash", "value":"", "source":"github_actions_artifact", "tlp":"TLP:RED"},
    ]
    for m in mocks:
        insert_ioc(m)
    print(f"[GitHub] {len(mocks)} IOC simulés")
    return len(mocks)


# ─────────────────────────────────────────────────────────────
# SOURCE 2 — Abuse.ch (URLhaus + MalwareBazaar) — 100% gratuit
# ─────────────────────────────────────────────────────────────

def collect_abusech_urlhaus() -> int:
    """Collecte les URLs malveillantes récentes depuis URLhaus (Abuse.ch)."""
    print("[Abuse.ch] Collecte URLhaus...")
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/",
            timeout=20
        )
        r.raise_for_status()
        data = r.json()
        urls = data.get("urls", [])
        count = 0
        for entry in urls:
            if entry.get("url_status") != "online":
                continue
            tags = entry.get("tags") or []
            # Filtrer seulement les IOC cloud/CI
            cloud_tags = ["aws","azure","gcp","docker","kubernetes","github","gitlab","s3","lambda"]
            if not any(t.lower() in cloud_tags for t in tags):
                continue
            ioc = {
                "type":   "url",
                "value":  entry.get("url","")[:500],
                "source": "abusech_urlhaus",
                "tlp":    "TLP:WHITE",  # URLhaus est public TLP:WHITE
            }
            insert_ioc(ioc)
            insert_enrichment({
                "ioc_value":       entry.get("url","")[:500],
                "provider":        "abusech_urlhaus",
                "score":           85.0,
                "malicious_count": 1,
                "total_engines":   1,
                "tags":            json.dumps(tags),
            })
            count += 1
        print(f"[Abuse.ch] {count} URLs cloud malveillantes collectées")
        if count == 0:
            return _mock_abusech()
        return count
    except Exception as e:
        print(f"[Abuse.ch] Erreur URLhaus: {e}")
        return _mock_abusech()


def collect_abusech_malwarebazaar() -> int:
    """Collecte les hashes malveillants récents depuis MalwareBazaar."""
    print("[Abuse.ch] Collecte MalwareBazaar...")
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "100"},
            timeout=20
        )
        r.raise_for_status()
        data = r.json()
        samples = data.get("data", [])
        count = 0
        cloud_tags = ["aws","azure","docker","kubernetes","container","ci","github","gitlab"]
        for s in samples[:50]:
            tags = s.get("tags") or []
            if not any(t.lower() in cloud_tags for t in (tags or [])):
                continue
            sha256 = s.get("sha256_hash", "")
            if not sha256:
                continue
            ioc = {
                "type":   "hash",
                "value":  sha256,
                "source": "abusech_malwarebazaar",
                "tlp":    "TLP:WHITE",
            }
            insert_ioc(ioc)
            insert_enrichment({
                "ioc_value":       sha256,
                "provider":        "malwarebazaar",
                "score":           95.0,
                "malicious_count": 1,
                "total_engines":   1,
                "tags":            json.dumps(tags or []),
            })
            count += 1
        print(f"[Abuse.ch] {count} hashes cloud collectés")
        return count
    except Exception as e:
        print(f"[Abuse.ch] Erreur MalwareBazaar: {e}")
        return 0


def _mock_abusech() -> int:
    """Simule des IOC Abuse.ch si pas de connectivité."""
    mocks = [
        {"type":"url",  "value":"https://s3.evil-bucket.aws-cdn-login.com/payload.sh", "source":"abusech_urlhaus", "tlp":"TLP:WHITE"},
        {"type":"url",  "value":"http://fake-docker-registry.io/ubuntu:latest/malware", "source":"abusech_urlhaus", "tlp":"TLP:WHITE"},
        {"type":"hash", "value":"", "source":"abusech_malwarebazaar", "tlp":"TLP:WHITE"},
        {"type":"hash", "value":"", "source":"abusech_malwarebazaar", "tlp":"TLP:WHITE"},
    ]
    for m in mocks:
        insert_ioc(m)
        insert_enrichment({
            "ioc_value": m["value"], "provider": "abusech_mock",
            "score": 90.0, "malicious_count": 9, "total_engines": 10,
            "tags": json.dumps(["cloud","malware"]),
        })
    print(f"[Abuse.ch] {len(mocks)} IOC simulés")
    return len(mocks)


# ─────────────────────────────────────────────────────────────
# SOURCE 3 — AlienVault OTX (Open Threat Exchange)
# ─────────────────────────────────────────────────────────────

def collect_otx_cloud_iocs() -> int:
    """Collecte les IOC cloud depuis AlienVault OTX pulses."""
    print("[OTX] Collecte AlienVault OTX...")
    if not OTX_API_KEY:
        print("[OTX] Pas de clé API — simulation")
        return _mock_otx()

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    # Pulses sur les thèmes cloud
    cloud_terms = ["kubernetes", "docker", "aws", "azure", "github-actions"]
    count = 0
    for term in cloud_terms[:2]:  # Limiter pour éviter le rate limit
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/search/pulses?q={term}&limit=5",
                headers=headers, timeout=15
            )
            r.raise_for_status()
            pulses = r.json().get("results", [])
            for pulse in pulses:
                for ind in pulse.get("indicators", [])[:5]:
                    ioc_type_map = {
                        "IPv4": "ip", "domain": "domain",
                        "URL": "url", "FileHash-SHA256": "hash",
                        "hostname": "domain",
                    }
                    ioc_type = ioc_type_map.get(ind.get("type",""), None)
                    if not ioc_type:
                        continue
                    ioc = {
                        "type":   ioc_type,
                        "value":  ind.get("indicator","")[:500],
                        "source": f"otx_pulse:{pulse.get('id','')}",
                        "tlp":    "TLP:WHITE",
                    }
                    insert_ioc(ioc)
                    insert_enrichment({
                        "ioc_value":       ind.get("indicator","")[:500],
                        "provider":        "alienvault_otx",
                        "score":           75.0,
                        "malicious_count": 1,
                        "total_engines":   1,
                        "tags":            json.dumps([term]),
                    })
                    count += 1
            time.sleep(1)
        except Exception as e:
            print(f"[OTX] Erreur pour '{term}': {e}")

    print(f"[OTX] {count} IOC collectés")
    if count == 0:
        return _mock_otx()
    return count


def _mock_otx() -> int:
    """Simule des IOC OTX."""
    mocks = [
        {"type":"ip",     "value":"185.220.101.34", "source":"otx_pulse:kubernetes_attack", "tlp":"TLP:WHITE"},
        {"type":"ip",     "value":"194.165.16.29",  "source":"otx_pulse:aws_abuse", "tlp":"TLP:WHITE"},
        {"type":"domain", "value":"kubernetes-dashboard.evil.com", "source":"otx_pulse:k8s", "tlp":"TLP:WHITE"},
        {"type":"domain", "value":"aws-signin-console.net", "source":"otx_pulse:phishing", "tlp":"TLP:WHITE"},
        {"type":"hash",   "value":"", "source":"otx_pulse:docker_malware", "tlp":"TLP:WHITE"},
    ]
    for m in mocks:
        insert_ioc(m)
        insert_enrichment({
            "ioc_value": m["value"], "provider": "otx_mock",
            "score": 75.0, "malicious_count": 3, "total_engines": 4,
            "tags": json.dumps(["cloud","apt"]),
        })
    print(f"[OTX] {len(mocks)} IOC simulés")
    return len(mocks)


# ─────────────────────────────────────────────────────────────
# SOURCE 4 — AWS GuardDuty (si clés AWS configurées)
# ─────────────────────────────────────────────────────────────

def collect_aws_guardduty() -> int:
    """Collecte les findings AWS GuardDuty."""
    if not AWS_ACCESS_KEY:
        print("[AWS] Pas de clés AWS — simulation GuardDuty")
        return _mock_guardduty()
    try:
        import boto3
        client = boto3.client(
            "guardduty",
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION,
        )
        detectors = client.list_detectors().get("DetectorIds", [])
        if not detectors:
            print("[AWS] Aucun détecteur GuardDuty actif")
            return 0
        detector_id = detectors[0]
        finding_ids = client.list_findings(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"severity": {"Gte": 4}}}
        ).get("FindingIds", [])[:10]
        findings = client.get_findings(
            DetectorId=detector_id, FindingIds=finding_ids
        ).get("Findings", [])
        count = 0
        for f in findings:
            sev   = f.get("Severity", 0)
            tlp   = "TLP:RED" if sev >= 7 else "TLP:AMBER"
            # Extraire IP depuis le finding
            remote = f.get("Service",{}).get("Action",{}).get("NetworkConnectionAction",{}).get("RemoteIpDetails",{})
            ip = remote.get("IpAddressV4","")
            if ip:
                insert_ioc({"type":"ip","value":ip,"source":f"aws_guardduty:{f.get('Id','')}","tlp":tlp})
                insert_enrichment({
                    "ioc_value": ip, "provider": "aws_guardduty",
                    "score": sev * 10, "malicious_count": 1, "total_engines": 1,
                    "tags": json.dumps([f.get("Type","")]),
                })
                count += 1
        print(f"[AWS] {count} IOC GuardDuty collectés")
        return count
    except ImportError:
        print("[AWS] boto3 non installé")
        return _mock_guardduty()
    except Exception as e:
        print(f"[AWS] Erreur GuardDuty: {e}")
        return _mock_guardduty()


def _mock_guardduty() -> int:
    """Simule des findings AWS GuardDuty."""
    mocks = [
        {"type":"ip", "value":"198.51.100.23", "source":"aws_guardduty:UnauthorizedAccess:EC2/SSHBruteForce", "tlp":"TLP:AMBER"},
        {"type":"ip", "value":"203.0.113.42",  "source":"aws_guardduty:Recon:EC2/PortProbeUnprotectedPort", "tlp":"TLP:AMBER"},
        {"type":"ip", "value":"198.51.100.99", "source":"aws_guardduty:CryptoCurrency:EC2/BitcoinTool", "tlp":"TLP:RED"},
        {"type":"domain", "value":"s3-malicious-exfil.amazonaws.com.evil.ru", "source":"aws_guardduty:Exfiltration:S3", "tlp":"TLP:RED"},
    ]
    for m in mocks:
        insert_ioc(m)
        insert_enrichment({
            "ioc_value": m["value"], "provider": "guardduty_mock",
            "score": 80.0 if "RED" in m["tlp"] else 55.0,
            "malicious_count": 8, "total_engines": 10,
            "tags": json.dumps(["aws","cloud","attack"]),
        })
    print(f"[AWS GuardDuty] {len(mocks)} IOC simulés")
    return len(mocks)


# ─────────────────────────────────────────────────────────────
# COLLECTEUR PRINCIPAL
# ─────────────────────────────────────────────────────────────

def run_ioc_collector() -> int:
    """Lance tous les collecteurs IOC dynamiques."""
    print("\n" + "="*50)
    print("  IOC Collector — Multi-Sources")
    print("="*50)
    total = 0
    total += collect_github_secrets()
    total += collect_abusech_urlhaus()
    total += collect_abusech_malwarebazaar()
    total += collect_otx_cloud_iocs()
    total += collect_aws_guardduty()

    # Stats finales
    with get_conn() as c:
        nb_ioc  = c.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
        nb_enr  = c.execute("SELECT COUNT(*) FROM enrichment").fetchone()[0]
        malicious = c.execute("SELECT COUNT(DISTINCT ioc_value) FROM enrichment WHERE score>50").fetchone()[0]

    print(f"\n[IOC] Collecte terminée : {total} nouveaux IOC")
    print(f"[IOC] Total en base : {nb_ioc} IOC — {nb_enr} enrichissements — {malicious} malveillants")
    return total


if __name__ == "__main__":
    init_db()
    run_ioc_collector()


def get_ioc_stats() -> dict:
    """Stats IOC pour le dashboard — avec résultats VT."""
    from database import get_conn
    with get_conn() as c:
        cols = [col[1] for col in c.execute("PRAGMA table_info(ioc)").fetchall()]
        has_vt = "vt_verdict" in cols

        total    = c.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
        by_type  = dict(c.execute("SELECT type, COUNT(*) FROM ioc GROUP BY type").fetchall())
        by_source= dict(c.execute("SELECT source, COUNT(*) FROM ioc GROUP BY source ORDER BY 2 DESC").fetchall())

        malicious  = c.execute("SELECT COUNT(*) FROM ioc WHERE vt_verdict='MALICIOUS'").fetchone()[0] if has_vt else 0
        suspicious = c.execute("SELECT COUNT(*) FROM ioc WHERE vt_verdict='SUSPICIOUS'").fetchone()[0] if has_vt else 0
        pending    = c.execute("SELECT COUNT(*) FROM ioc WHERE vt_verdict='PENDING'").fetchone()[0] if has_vt else total
        by_vt      = dict(c.execute("SELECT vt_verdict, COUNT(*) FROM ioc GROUP BY vt_verdict").fetchall()) if has_vt else {}

        # Top IOC malveillants VT
        top_malicious = []
        if has_vt:
            rows = c.execute("""
                SELECT value, type, source, vt_score, vt_malicious
                FROM ioc WHERE vt_verdict IN ('MALICIOUS','SUSPICIOUS')
                ORDER BY vt_malicious DESC LIMIT 10
            """).fetchall()
            top_malicious = [{"value": r[0], "type": r[1], "source": r[2],
                               "vt_score": r[3], "vt_malicious": r[4]} for r in rows]

    return {
        "total":         total,
        "malicious":     malicious,
        "suspicious":    suspicious,
        "pending_vt":    pending,
        "by_type":       by_type,
        "by_source":     by_source,
        "by_vt_verdict": by_vt,
        "top_malicious": top_malicious,
        "top_threats":   []
    }
