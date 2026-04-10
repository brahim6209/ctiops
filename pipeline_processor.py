"""
Pipeline de traitement automatique CTIOps
Pour chaque build reçu, applique tous les algorithmes disponibles
même si certains scanners sont absents.
"""
import json, sqlite3, re
from database import get_conn

# ─── 1. NORMALISATION UNIVERSELLE ────────────────────────────────────────────

def normalize_finding(raw: dict, tool: str) -> dict:
    """Normalise n'importe quel finding vers le schéma interne CTIOps."""
    sev_map = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"UNKNOWN":0,
               "BLOCKER":4,"MAJOR":3,"MINOR":1,"ERROR":3,"WARNING":2,
               "4":4,"3":3,"2":2,"1":1,"0":0}

    raw_sev = str(raw.get("severity", raw.get("riskcode", raw.get("priority","UNKNOWN")))).upper()
    sev_int = sev_map.get(raw_sev, 0)
    sev_str = ["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"][min(sev_int,4)]

    cvss = float(raw.get("cvss") or raw.get("cvssScore") or
                 raw.get("cvssv3",{}).get("baseScore",0) if isinstance(raw.get("cvssv3"),dict)
                 else raw.get("cvssv3",0) or 0)

    return {
        "id":          raw.get("id") or raw.get("VulnerabilityID") or raw.get("check_id") or raw.get("pluginid","UNKNOWN"),
        "severity":    sev_str,
        "severity_int":sev_int,
        "cvss":        cvss,
        "package":     raw.get("package") or raw.get("PkgName") or raw.get("packageName",""),
        "version":     raw.get("version") or raw.get("InstalledVersion",""),
        "fixed":       raw.get("fixed") or raw.get("FixedVersion",""),
        "file":        raw.get("file") or raw.get("path") or raw.get("component",""),
        "title":       raw.get("title") or raw.get("message") or raw.get("name") or raw.get("check_id",""),
        "description": str(raw.get("description",""))[:300],
        "tool":        tool,
        "cwe":         str(raw.get("cwe") or raw.get("CweIDs",[""])[0] if isinstance(raw.get("CweIDs"),list) else ""),
        "url":         raw.get("url") or raw.get("references",[""])[0] if isinstance(raw.get("references"),list) else "",
        "rule_id":     raw.get("rule_id") or raw.get("RuleID") or raw.get("id",""),
        "secret_hint": raw.get("secret_hint") or raw.get("secret","")[:30],
        "entropy":     raw.get("entropy") or raw.get("Entropy") or 0,
        "match":       raw.get("match") or raw.get("Match",""),
    }

# ─── 2. REALITY SCORE (sans ML externe) ─────────────────────────────────────

def compute_reality_score(finding: dict, cisa_kev_ids: set) -> float:
    """Calcule le Reality Score pour un finding normalisé."""
    cvss       = min(float(finding.get("cvss") or 0), 10.0)
    sev_int    = finding.get("severity_int", 0)
    kev_flag   = 1 if finding.get("id","") in cisa_kev_ids else 0
    has_fix    = 1 if finding.get("fixed","") else 0
    tool       = finding.get("tool","")

    # Poids par outil
    tool_weight = {
        "trivy":1.0,"owasp":0.9,"snyk":1.0,"grype":1.0,
        "owasp-zap":0.85,"semgrep":0.8,"sonarqube":0.7,
        "gitleaks":0.95,"checkov":0.75
    }.get(tool, 0.7)

    score = (
        (cvss / 10.0) * 35 +
        (sev_int / 4.0) * 25 +
        kev_flag * 20 +
        (1 if cvss >= 9.0 else 0) * 10 +
        (1 - has_fix) * 5 +
        (1 if tool in ["gitleaks"] else 0) * 5
    ) * tool_weight

    return round(min(score, 100), 2)

# ─── 3. CLASSIFICATION NLP SIMPLIFIÉE ───────────────────────────────────────

CATEGORIES = {
    "RCE":            ["remote code","rce","arbitrary code","code execution","command injection","shell"],
    "INJECTION":      ["sql injection","sqli","injection","xpath","ldap injection","nosql"],
    "AUTH_BYPASS":    ["authentication","auth bypass","unauthorized","privilege","improper access"],
    "PRIVESC":        ["privilege escalation","local privilege","sudo","setuid","root"],
    "XSS":            ["cross-site scripting","xss","script injection","stored xss","reflected"],
    "SSRF":           ["server-side request","ssrf","internal network","metadata service"],
    "PATH_TRAVERSAL": ["path traversal","directory traversal","lfi","local file","../"],
    "CRYPTO":         ["cryptographic","weak cipher","md5","sha1","hardcoded","insecure hash"],
    "SECRET_LEAK":    ["secret","api key","password","token","credential","private key"],
    "CONTAINER":      ["container escape","docker","kubernetes","namespace","pod security"],
    "SUPPLY_CHAIN":   ["dependency","package","npm","pypi","supply chain","malicious package"],
    "MISCONFIG":      ["misconfiguration","default credential","exposed","open port","publicly"],
    "DOS":            ["denial of service","dos","crash","memory exhaustion","infinite loop"],
}

def classify_finding(finding: dict) -> str:
    """Classification NLP basée sur mots-clés dans titre/description."""
    text = (finding.get("title","") + " " +
            finding.get("description","") + " " +
            finding.get("id","")).lower()

    scores = {}
    for cat, keywords in CATEGORIES.items():
        scores[cat] = sum(1 for kw in keywords if kw in text)

    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "OTHER"

# ─── 4. ATTACK PATH PREDICTION ──────────────────────────────────────────────

# Matrice de transition simplifiée (Chaîne de Markov)
ATTACK_TRANSITIONS = {
    "RCE":            [("PRIVESC",0.7),("CONTAINER",0.5),("SUPPLY_CHAIN",0.3)],
    "INJECTION":      [("AUTH_BYPASS",0.8),("SECRET_LEAK",0.6),("RCE",0.4)],
    "AUTH_BYPASS":    [("PRIVESC",0.75),("SECRET_LEAK",0.65),("RCE",0.5)],
    "SECRET_LEAK":    [("AUTH_BYPASS",0.9),("PRIVESC",0.6),("SUPPLY_CHAIN",0.4)],
    "PRIVESC":        [("CONTAINER",0.7),("RCE",0.6),("MISCONFIG",0.4)],
    "XSS":            [("AUTH_BYPASS",0.7),("SECRET_LEAK",0.5),("INJECTION",0.3)],
    "SSRF":           [("RCE",0.6),("SECRET_LEAK",0.7),("MISCONFIG",0.5)],
    "CONTAINER":      [("PRIVESC",0.8),("RCE",0.6),("MISCONFIG",0.5)],
    "MISCONFIG":      [("AUTH_BYPASS",0.6),("SECRET_LEAK",0.5),("CONTAINER",0.4)],
    "PATH_TRAVERSAL": [("SECRET_LEAK",0.75),("RCE",0.5),("AUTH_BYPASS",0.4)],
    "SUPPLY_CHAIN":   [("RCE",0.8),("PRIVESC",0.6),("SECRET_LEAK",0.5)],
    "CRYPTO":         [("AUTH_BYPASS",0.7),("SECRET_LEAK",0.6)],
    "DOS":            [("MISCONFIG",0.4)],
    "OTHER":          [("MISCONFIG",0.3)],
}

MITRE_MAP = {
    "RCE":            "T1059 - Command & Scripting Interpreter",
    "INJECTION":      "T1190 - Exploit Public-Facing Application",
    "AUTH_BYPASS":    "T1078 - Valid Accounts",
    "SECRET_LEAK":    "T1552 - Unsecured Credentials",
    "PRIVESC":        "T1068 - Exploitation for Privilege Escalation",
    "XSS":            "T1189 - Drive-by Compromise",
    "SSRF":           "T1090 - Proxy",
    "CONTAINER":      "T1611 - Escape to Host",
    "MISCONFIG":      "T1562 - Impair Defenses",
    "PATH_TRAVERSAL": "T1083 - File and Directory Discovery",
    "SUPPLY_CHAIN":   "T1195 - Supply Chain Compromise",
    "CRYPTO":         "T1600 - Weaken Encryption",
    "DOS":            "T1499 - Endpoint Denial of Service",
}

def predict_attack_path(category: str, reality_score: float) -> dict:
    """Prédit le chemin d'attaque probable depuis une catégorie."""
    transitions = ATTACK_TRANSITIONS.get(category, [])
    path = [category]
    visited = {category}
    current = category

    for _ in range(3):
        next_steps = [(t, p) for t, p in ATTACK_TRANSITIONS.get(current, [])
                      if t not in visited and p * (reality_score/100) > 0.2]
        if not next_steps:
            break
        next_steps.sort(key=lambda x: -x[1])
        best = next_steps[0][0]
        path.append(best)
        visited.add(best)
        current = best

    return {
        "path":         path,
        "mitre":        [MITRE_MAP.get(p, p) for p in path],
        "risk_score":   round(reality_score * len(path) / 10, 2),
        "kill_chain":   " → ".join(path),
        "transitions":  transitions[:3]
    }

# ─── 5. PIPELINE PRINCIPAL ──────────────────────────────────────────────────

def process_build(project: str, build: str, tool: str, raw_findings: list) -> dict:
    """
    Traitement complet d'un build :
    1. Normalisation
    2. Reality Score
    3. Classification NLP
    4. Prédiction chemin d'attaque
    5. Stockage enrichi
    """
    # Charger CISA KEV depuis la DB
    try:
        conn = get_conn()
        kev_rows = conn.execute("SELECT cve_id FROM cve_cache WHERE cisa_kev=1").fetchall()
        cisa_kev_ids = {r[0] for r in kev_rows}
    except Exception:
        cisa_kev_ids = set()

    results = []
    attack_paths = []

    for raw in raw_findings:
        # 1. Normalise
        finding = normalize_finding(raw, tool)

        # 2. Reality Score
        finding["reality_score"] = compute_reality_score(finding, cisa_kev_ids)

        # 3. Classification NLP
        finding["category"] = classify_finding(finding)

        # 4. Prédiction chemin d'attaque (seulement si score > 30)
        if finding["reality_score"] > 30:
            ap = predict_attack_path(finding["category"], finding["reality_score"])
            finding["attack_path"] = ap["kill_chain"]
            finding["mitre"]       = ap["mitre"][0] if ap["mitre"] else ""
            attack_paths.append({
                "cve_id":    finding["id"],
                "project":   project,
                "build":     build,
                "tool":      tool,
                "technique_from": finding["category"],
                "technique_to":   ap["path"][1] if len(ap["path"]) > 1 else finding["category"],
                "tactic":    ap["mitre"][0] if ap["mitre"] else "",
                "kill_chain":ap["kill_chain"],
                "risk_score":ap["risk_score"],
                "probability": ap["transitions"][0][1] if ap["transitions"] else 0,
            })
        else:
            finding["attack_path"] = ""
            finding["mitre"] = ""

        results.append(finding)

    # 5. Persiste les chemins d'attaque enrichis
    try:
        conn = get_conn()
        for ap in attack_paths:
            conn.execute("""
                INSERT OR IGNORE INTO attack_paths
                (cve_id, technique_from, technique_to, tactic,
                 probability, kill_chain, risk_score, created_at)
                VALUES (?,?,?,?,?,?,?,datetime('now'))
            """, (ap["cve_id"], ap["technique_from"], ap["technique_to"],
                  ap["tactic"], ap["probability"], ap["kill_chain"], ap["risk_score"]))
        conn.commit()
    except Exception as e:
        print(f"[pipeline] attack_paths error: {e}")

    # Stats globales du build
    crits  = sum(1 for f in results if f["severity"] == "CRITICAL")
    highs  = sum(1 for f in results if f["severity"] == "HIGH")
    avg_rs = round(sum(f["reality_score"] for f in results) / len(results), 2) if results else 0
    cats   = {}
    for f in results:
        cats[f["category"]] = cats.get(f["category"], 0) + 1

    return {
        "project":      project,
        "build":        build,
        "tool":         tool,
        "total":        len(results),
        "critical":     crits,
        "high":         highs,
        "avg_reality":  avg_rs,
        "categories":   cats,
        "attack_paths": len(attack_paths),
        "findings":     results
    }
