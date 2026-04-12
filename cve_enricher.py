"""
cve_enricher.py — Enrichissement complet des CVE
1. Classification type attaque (NLP sur description)
2. Vérification exploit via VirusTotal
3. Mapping MITRE ATT&CK automatique
4. Recommandations posture par type
5. Score de confiance (est-ce réel ?)
"""
import os, re, json, requests, time
from database import get_conn
from dotenv import load_dotenv

load_dotenv('/home/br1kx/cti/ctiops/.env')
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─── NLP Classifier ──────────────────────────────────────────────────────────
try:
    from nlp_classifier import NLPClassifier as _NLPClassifier
    _nlp = _NLPClassifier.get()
except Exception as _e:
    _nlp = None
    print(f"[CVE Enricher] NLP non disponible: {_e}")

# ── POC LINK FINDER ───────────────────────────────────────────────
def find_poc_links(cve_id: str) -> dict:
    """Trouver les liens PoC publics pour un CVE."""
    poc_links = []
    
    # 1. GitHub Advisory / Search
    try:
        r = requests.get(
            f"https://api.github.com/search/repositories",
            params={"q": f"{cve_id} poc exploit", "sort": "stars", "per_page": 3},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10
        )
        if r.status_code == 200:
            for repo in r.json().get("items", [])[:3]:
                if any(kw in repo.get("name","").lower() or kw in repo.get("description","").lower() 
                       for kw in ["poc","exploit","cve"]):
                    poc_links.append({
                        "source": "GitHub",
                        "url":    repo["html_url"],
                        "name":   repo.get("full_name",""),
                        "stars":  repo.get("stargazers_count",0)
                    })
    except:
        pass
    
    # 2. ExploitDB search
    try:
        r = requests.get(
            f"https://www.exploit-db.com/search",
            params={"cve": cve_id},
            headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data", [])[:2]:
                edb_id = item.get("id","")
                if edb_id:
                    poc_links.append({
                        "source": "ExploitDB",
                        "url":    f"https://www.exploit-db.com/exploits/{edb_id}",
                        "name":   item.get("description","")[:60],
                        "type":   item.get("type","")
                    })
    except:
        pass
    
    # 3. NVD references (CVE page directe)
    poc_links.append({
        "source": "NVD",
        "url":    f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "name":   f"NVD - {cve_id}",
        "type":   "advisory"
    })
    
    return {
        "poc_available": len(poc_links) > 1,
        "poc_links":     poc_links,
        "poc_count":     len(poc_links)
    }


# ── CLASSIFICATION TYPE ATTAQUE ────────────────────────────────────
ATTACK_PATTERNS = {
    "PRIVESC": [
        "privilege escalation", "privilege elevation", "local privilege",
        "root access", "sudo", "suid", "setuid", "kernel privilege",
        "arbitrary code execution.*root", "gain.*privilege"
    ],
    "RCE": [
        "remote code execution", "arbitrary code execution",
        "command injection", "code injection", "os command",
        "shell injection", "execute arbitrary", "rce"
    ],
    "SQLI": [
        "sql injection", "sql query", "database query",
        "blind sql", "union select", "sqlinjection"
    ],
    "SSRF": [
        "server.side request forgery", "ssrf", "internal network",
        "internal service", "metadata service", "169.254",
        "aws metadata", "cloud metadata"
    ],
    "AUTH_BYPASS": [
        "authentication bypass", "authentication flaw",
        "unauthorized access", "improper authentication",
        "missing authentication", "weak authentication",
        "bypass.*auth", "unauthenticated"
    ],
    "XXE": [
        "xml external entity", "xxe", "xml injection",
        "external entity"
    ],
    "PATH_TRAVERSAL": [
        "path traversal", "directory traversal", r"\.\./",
        "local file inclusion", "lfi", "file inclusion"
    ],
    "CONTAINER_ESCAPE": [
        "container escape", "docker escape", "namespace escape",
        "cgroup escape", "kubernetes escape", "pod escape",
        "privileged container"
    ],
    "SUPPLY_CHAIN": [
        "supply chain", "dependency confusion", "typosquatting",
        "malicious package", "build pipeline", "ci/cd",
        "github action", "npm package", "pypi package"
    ],
    "IDOR": [
        "insecure direct object", "idor", "broken access control",
        "horizontal privilege", "object reference"
    ],
    "DOS": [
        "denial of service", "dos attack", "resource exhaustion",
        "infinite loop", "memory exhaustion", "cpu exhaustion",
        "crash", "hang", "unresponsive"
    ],
    "INFO_DISCLOSURE": [
        "information disclosure", "sensitive information",
        "credentials exposure", "token exposure", "api key",
        "secret exposure", "data exposure"
    ],
    "CLOUD_SPECIFIC": [
        "iam", "s3 bucket", "azure ad", "gcp iam",
        "cloud storage", "blob storage", "ecr", "eks",
        "lambda", "azure function", "cloud function"
    ]
}

# Mapping MITRE ATT&CK par type
MITRE_MAPPING = {
    "PRIVESC":         {"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "RCE":             {"technique": "T1190", "name": "Exploit Public-Facing Application",      "tactic": "Initial Access"},
    "SQLI":            {"technique": "T1190", "name": "Exploit Public-Facing Application",      "tactic": "Initial Access"},
    "SSRF":            {"technique": "T1078", "name": "Valid Accounts — SSRF",                  "tactic": "Defense Evasion"},
    "AUTH_BYPASS":     {"technique": "T1078", "name": "Valid Accounts",                         "tactic": "Defense Evasion"},
    "XXE":             {"technique": "T1059", "name": "Command and Scripting Interpreter",       "tactic": "Execution"},
    "PATH_TRAVERSAL":  {"technique": "T1083", "name": "File and Directory Discovery",            "tactic": "Discovery"},
    "CONTAINER_ESCAPE":{"technique": "T1611", "name": "Escape to Host",                         "tactic": "Privilege Escalation"},
    "SUPPLY_CHAIN":    {"technique": "T1195", "name": "Supply Chain Compromise",                 "tactic": "Initial Access"},
    "IDOR":            {"technique": "T1548", "name": "Abuse Elevation Control Mechanism",       "tactic": "Privilege Escalation"},
    "DOS":             {"technique": "T1499", "name": "Endpoint Denial of Service",              "tactic": "Impact"},
    "INFO_DISCLOSURE": {"technique": "T1552", "name": "Unsecured Credentials",                   "tactic": "Credential Access"},
    "CLOUD_SPECIFIC":  {"technique": "T1078.004", "name": "Cloud Accounts",                      "tactic": "Defense Evasion"},
    "UNKNOWN":         {"technique": "T1190", "name": "Exploit Public-Facing Application",       "tactic": "Initial Access"},
}

# Recommandations par type
RECOMMENDATIONS = {
    "PRIVESC":    ["Apply least privilege principle", "Enable SELinux/AppArmor", "Patch kernel immediately", "Audit SUID binaries"],
    "RCE":        ["Patch immediately — P0", "Enable WAF rules", "Network segmentation", "Disable unused services"],
    "SQLI":       ["Use parameterized queries", "Deploy WAF", "Input validation", "Least privilege DB accounts"],
    "SSRF":       ["Block metadata endpoints (169.254.169.254)", "Egress filtering", "Validate URLs server-side", "IMDSv2 enforcement"],
    "AUTH_BYPASS":["MFA enforcement", "Rotate credentials immediately", "Audit access logs", "Zero Trust implementation"],
    "CONTAINER_ESCAPE": ["Non-root containers", "Read-only filesystem", "Drop capabilities", "Pod Security Standards"],
    "SUPPLY_CHAIN":["Pin dependency versions", "Verify checksums", "Use private registries", "SBOM generation"],
    "CLOUD_SPECIFIC": ["IAM least privilege", "Enable CloudTrail", "Resource tagging", "Config Rules"],
    "DOS":        ["Rate limiting", "Load balancer config", "Resource limits", "Auto-scaling"],
    "INFO_DISCLOSURE": ["Secret rotation", "Vault integration", "Audit API responses", "Data masking"],
}

def classify_attack_type(description: str) -> str:
    """Classifier le type d'attaque depuis la description CVE.
    
    Priorité:
    1. NLP (TF-IDF + LogisticRegression) si modèle disponible
    2. Fallback regex si NLP absent ou confidence < 0.30
    """
    if not description:
        return "UNKNOWN"
    
    # ── NLP classifier (prioritaire) ──
    if _nlp is not None and _nlp.is_ready:
        result = _nlp.classify_with_confidence(description)
        if result["attack_type"] != "UNKNOWN":
            return result["attack_type"]
    
    # ── Fallback regex ──
    desc_lower = description.lower()
    scores = {}
    for attack_type, patterns in ATTACK_PATTERNS.items():
        score = 0
        for pattern in patterns:
            if re.search(pattern, desc_lower):
                score += 1
        if score > 0:
            scores[attack_type] = score
    if not scores:
        return "UNKNOWN"
    return max(scores, key=scores.get)


def get_mitre_for_type(attack_type: str) -> dict:
    return MITRE_MAPPING.get(attack_type, MITRE_MAPPING["UNKNOWN"])


def get_recommendations(attack_type: str) -> list:
    return RECOMMENDATIONS.get(attack_type, ["Apply vendor patch", "Monitor for exploitation", "Review security controls"])


def verify_exploit_virustotal(cve_id: str) -> dict:
    """Vérifier via VirusTotal si un exploit existe pour ce CVE."""
    if not VT_KEY:
        return {"vt_verified": False, "vt_error": "No API key"}
    try:
        # Search VT for CVE
        headers = {"x-apikey": VT_KEY, "Accept": "application/json"}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/search",
            params={"query": cve_id},
            headers=headers,
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            items = data.get("data", [])
            exploit_found = len(items) > 0
            malicious_count = sum(
                1 for item in items
                if item.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
            )
            return {
                "vt_verified":      True,
                "vt_exploit_found": exploit_found,
                "vt_item_count":    len(items),
                "vt_malicious":     malicious_count,
                "vt_confidence":    "HIGH" if malicious_count > 3 else "MEDIUM" if exploit_found else "LOW"
            }
        elif r.status_code == 429:
            return {"vt_verified": False, "vt_error": "Rate limited"}
        else:
            return {"vt_verified": False, "vt_error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"vt_verified": False, "vt_error": str(e)}


def compute_reality_score(cve: dict, vt_result: dict = None) -> dict:
    """
    Score de priorisation CVE basé sur 3 sources fiables :
    - CISA KEV  : exploitation active confirmée (+40)
    - EPSS      : probabilité exploitation 30j FIRST.org (+25/+10)
    - Exploit   : exploit public ExploitDB/GitHub (+20)
    - CVSS      : sévérité technique NIST (+10 si >= 9.0)
    Max = 40+25+20+10 = 95 pts
    Note : VT non utilisé ici — VT sert pour IOC (IPs/URLs), pas CVE.
    """
    score = 0
    evidence = []

    # 1. CISA KEV — source officielle la plus fiable (+40)
    if cve.get("actively_exploited"):
        score += 40
        evidence.append("CISA KEV — exploitation active confirmée")

    # 2. EPSS — probabilité exploitation dans 30j (+25 ou +10)
    epss = cve.get("epss_score") or 0
    if epss >= 0.5:
        score += 25
        evidence.append(f"EPSS={epss:.1%} — probabilité élevée")
    elif epss >= 0.1:
        score += 10
        evidence.append(f"EPSS={epss:.1%} — probabilité modérée")

    # 3. Exploit public connu (+20)
    if cve.get("has_exploit"):
        score += 20
        evidence.append(f"Exploit public via {cve.get('exploit_source', 'unknown')}")

    # 4. CVSS critique (+10)
    cvss = cve.get("cvss_score") or 0
    if cvss >= 9.0:
        score += 10
        evidence.append(f"CVSS={cvss} — critique")

    score = min(score, 100)
    if score >= 75:   confidence = "CONFIRMED"
    elif score >= 50: confidence = "LIKELY"
    elif score >= 25: confidence = "POSSIBLE"
    else:             confidence = "UNVERIFIED"

    return {
        "reality_score":    score,
        "reality_level":    confidence,
        "reality_evidence": evidence
    }

def enrich_cve(cve_id: str, use_vt: bool = True) -> dict:
    """Enrichir une CVE complètement."""
    with get_conn() as c:
        row = c.execute("SELECT * FROM cve WHERE id=?", (cve_id,)).fetchone()
        if not row:
            return {"error": f"CVE {cve_id} not found"}
        cve = dict(row)

    # 1. Classification
    attack_type = classify_attack_type(cve.get("description", ""))
    mitre = get_mitre_for_type(attack_type)
    recs  = get_recommendations(attack_type)

    # 2. VT verification (avec rate limit)
    vt_result = {}
    if use_vt and VT_KEY:
        vt_result = verify_exploit_virustotal(cve_id)
        time.sleep(0.5)  # Rate limit VT free = 4 req/min

    # 3. Reality score
    reality = compute_reality_score(cve, vt_result)

    # 4. Assembler résultat complet
    result = {
        **cve,
        "attack_type":       attack_type,
        "mitre_technique":   mitre["technique"],
        "mitre_name":        mitre["name"],
        "mitre_tactic":      mitre["tactic"],
        "recommendations":   recs,
        **vt_result,
        **reality,
        "enriched": True
    }

    # 5. Sauvegarder en DB
    with get_conn() as c:
        c.execute("""
            UPDATE cve SET
                attack_type     = ?,
                mitre_technique = ?,
                mitre_tactic    = ?,
                recommendations = ?,
                reality_score   = ?,
                reality_level   = ?,
                vt_verified     = ?,
                vt_exploit_found= ?
            WHERE id = ?
        """, (
            attack_type,
            mitre["technique"],
            mitre["tactic"],
            json.dumps(recs),
            reality["reality_score"],
            reality["reality_level"],
            vt_result.get("vt_verified", False),
            vt_result.get("vt_exploit_found", False),
            cve_id
        ))

    return result


def enrich_all_cves(limit: int = 100, use_vt: bool = True) -> dict:
    """Enrichir toutes les CVE non encore enrichies."""
    with get_conn() as c:
        # Ajouter colonnes si manquantes
        existing = [col[1] for col in c.execute("PRAGMA table_info(cve)").fetchall()]
        new_cols = [
            ("attack_type",      "TEXT"),
            ("mitre_technique",  "TEXT"),
            ("mitre_tactic",     "TEXT"),
            ("recommendations",  "TEXT"),
            ("reality_score",    "INTEGER"),
            ("reality_level",    "TEXT"),
            ("vt_verified",      "INTEGER DEFAULT 0"),
            ("vt_exploit_found", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_type in new_cols:
            if col_name not in existing:
                c.execute(f"ALTER TABLE cve ADD COLUMN {col_name} {col_type}")
                print(f"  Colonne ajoutée: {col_name}")

        # CVE non enrichies
        cves = c.execute("""
            SELECT id FROM cve
            WHERE attack_type IS NULL
            ORDER BY
                CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                              WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,
                COALESCE(cvss_score, 0) DESC
            LIMIT ?
        """, (limit,)).fetchall()

    cve_ids = [r[0] for r in cves]
    print(f"[Enricher] {len(cve_ids)} CVE à enrichir...")

    results = {"enriched": 0, "errors": 0, "types": {}}

    for i, cve_id in enumerate(cve_ids):
        try:
            r = enrich_cve(cve_id, use_vt=use_vt)
            results["enriched"] += 1
            t = r.get("attack_type", "UNKNOWN")
            results["types"][t] = results["types"].get(t, 0) + 1
            if (i+1) % 20 == 0:
                print(f"  {i+1}/{len(cve_ids)} enrichies...")
        except Exception as e:
            results["errors"] += 1
            print(f"  Erreur {cve_id}: {e}")

    print(f"[Enricher] Terminé: {results['enriched']} enrichies | Types: {results['types']}")
    return results


def get_attack_type_stats() -> dict:
    """Stats des types d'attaque pour le dashboard."""
    with get_conn() as c:
        rows = c.execute("""
            SELECT
                attack_type,
                COUNT(*) as total,
                SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN actively_exploited=1 THEN 1 ELSE 0 END) as kev,
                SUM(CASE WHEN vt_exploit_found=1 THEN 1 ELSE 0 END) as vt_confirmed,
                AVG(cvss_score) as avg_cvss,
                AVG(reality_score) as avg_reality
            FROM cve
            WHERE attack_type IS NOT NULL
            GROUP BY attack_type
            ORDER BY critical DESC, total DESC
        """).fetchall()

    return {
        "by_type": [dict(r) for r in rows],
        "total":   sum(r["total"] for r in rows)
    }


def get_cve_detail(cve_id: str) -> dict:
    """Détail complet d'une CVE pour le click-through."""
    with get_conn() as c:
        row = c.execute("SELECT * FROM cve WHERE id=?", (cve_id,)).fetchone()
        if not row:
            return {"error": "Not found"}
        cve = dict(row)

    # Parser JSON fields
    try:
        cve["recommendations"] = json.loads(cve.get("recommendations") or "[]")
    except:
        cve["recommendations"] = []
    try:
        cve["keywords"] = json.loads(cve.get("keywords") or "[]")
    except:
        cve["keywords"] = []

    # Si pas encore enrichi, enrichir maintenant
    if not cve.get("attack_type"):
        enriched = enrich_cve(cve_id, use_vt=True)
        cve.update(enriched)

    # MITRE complet
    attack_type = cve.get("attack_type", "UNKNOWN")
    mitre = get_mitre_for_type(attack_type)
    cve["mitre"] = mitre

    # Kill chain stage
    cve["kill_chain_stage"] = _get_kill_chain_stage(attack_type)

    # Patch priority
    cve["patch_priority"] = _get_patch_priority(cve)

    # PoC Links
    try:
        poc = find_poc_links(cve_id)
        cve.update(poc)
    except Exception as e:
        cve["poc_links"] = []
        cve["poc_available"] = False

    return cve


def _get_kill_chain_stage(attack_type: str) -> dict:
    stages = {
        "SUPPLY_CHAIN":    {"id": 2, "name": "Weaponization"},
        "SSRF":            {"id": 3, "name": "Delivery"},
        "RCE":             {"id": 3, "name": "Delivery"},
        "SQLI":            {"id": 3, "name": "Delivery"},
        "AUTH_BYPASS":     {"id": 4, "name": "Exploitation"},
        "PRIVESC":         {"id": 5, "name": "Installation"},
        "CONTAINER_ESCAPE":{"id": 5, "name": "Installation"},
        "CLOUD_SPECIFIC":  {"id": 6, "name": "Command & Control"},
        "INFO_DISCLOSURE": {"id": 7, "name": "Actions on Objectives"},
    }
    return stages.get(attack_type, {"id": 4, "name": "Exploitation"})


def _get_patch_priority(cve: dict) -> str:
    if cve.get("actively_exploited"):
        return "P0-IMMEDIATE"
    if (cve.get("cvss_score") or 0) >= 9.0 and cve.get("has_exploit"):
        return "P1-URGENT"
    if (cve.get("cvss_score") or 0) >= 7.0:
        return "P2-HIGH"
    return "P3-MONITOR"


if __name__ == "__main__":
    print("=== Test enrichissement CVE ===")
    # Test sans VT d'abord (rapide)
    r = enrich_all_cves(limit=50, use_vt=False)
    print(f"Types d'attaque détectés: {r['types']}")
    stats = get_attack_type_stats()
    print(f"\nStats par type:")
    for t in stats["by_type"][:10]:
        print(f"  {t['attack_type']:20} total={t['total']:3} critical={t['critical']:3} kev={t['kev']:2}")
