"""
devsecops_collector.py — Universal DevSecOps Collector v2.0
Auto-detection scanner + Normalisation + ML Scoring
"""
import json, datetime
from database import get_conn

MITRE_BY_TYPE = {
    "secret":     {"id": "T1552.001", "name": "Credentials In Files",    "stage": 3},
    "jwt":        {"id": "T1552",     "name": "Unsecured Credentials",   "stage": 3},
    "api_key":    {"id": "T1552",     "name": "Unsecured Credentials",   "stage": 3},
    "rce":        {"id": "T1059",     "name": "Command Execution",       "stage": 4},
    "injection":  {"id": "T1190",     "name": "Exploit Public App",      "stage": 3},
    "privesc":    {"id": "T1068",     "name": "Privilege Escalation",    "stage": 4},
    "dependency": {"id": "T1195",     "name": "Supply Chain Compromise", "stage": 3},
    "misconfig":  {"id": "T1578",     "name": "Modify Cloud Compute",    "stage": 5},
    "default":    {"id": "T1190",     "name": "Exploit Public App",      "stage": 3},
}

def detect_scanner(report, tool_hint=""):
    if tool_hint and tool_hint.lower() in ("gitleaks","trivy","owasp","sonarqube","semgrep","snyk","custom"):
        return tool_hint.lower()
    if isinstance(report, list) and report:
        first = report[0] if isinstance(report[0], dict) else {}
        if all(k in first for k in ("RuleID","Secret","Entropy")):
            return "gitleaks"
        if all(k in first for k in ("check_id","path","extra")):
            return "semgrep"
    if isinstance(report, dict):
        if "Results" in report and "ArtifactType" in report: return "trivy"
        if "SchemaVersion" in report and "Results" in report: return "trivy"
        if "dependencies" in report: return "owasp"
        if "issues" in report and "components" in report: return "sonarqube"
        if "vulnerabilities" in report and "packageManager" in report: return "snyk"
    return "custom"

def ml_score(finding, scanner):
    score = 0
    finding_type = "default"
    if scanner == "gitleaks":
        rule = finding.get("RuleID","").lower()
        entropy = float(finding.get("Entropy", 0))
        fpath = finding.get("File","").lower()
        if "telegram" in rule or "bot" in rule: finding_type="token"; score=70
        elif "jwt" in rule or "secret" in rule: finding_type="jwt"; score=75
        elif "api" in rule or "key" in rule: finding_type="api_key"; score=65
        elif "password" in rule: finding_type="secret"; score=80
        else: finding_type="secret"; score=60
        score += min(20, int(entropy*3))
        if any(f in fpath for f in ["application.properties","config",".env","secret"]): score+=15
        if any(f in fpath for f in ["src/main","prod"]): score+=10
    elif scanner == "trivy":
        m = {"CRITICAL":90,"HIGH":70,"MEDIUM":50,"LOW":20,"UNKNOWN":30}
        score = m.get(finding.get("Severity","UNKNOWN").upper(), 30)
        finding_type = "dependency"
        if finding.get("FixedVersion"): score += 10
    elif scanner == "owasp":
        m = {"CRITICAL":90,"HIGH":70,"MEDIUM":50,"LOW":20,"INFO":10}
        score = m.get(finding.get("severity","MEDIUM").upper(), 40)
        finding_type = "dependency"
        cvss = finding.get("cvssv3",{})
        if cvss: score = max(score, int(cvss.get("baseScore",0)*10))
    elif scanner == "sonarqube":
        m = {"BLOCKER":90,"CRITICAL":80,"MAJOR":60,"MINOR":30,"INFO":10}
        score = m.get(finding.get("severity","MAJOR").upper(), 40)
        finding_type = "injection" if "vulnerability" in finding.get("type","").lower() else "misconfig"
    score = min(100, max(0, score))
    sev = "CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=40 else "LOW"
    return {"score": score, "severity": sev, "finding_type": finding_type,
            "mitre": MITRE_BY_TYPE.get(finding_type, MITRE_BY_TYPE["default"])}

def normalize_gitleaks(report, project, metadata):
    incidents = []
    for f in (report if isinstance(report,list) else []):
        if not isinstance(f, dict): continue
        ml = ml_score(f, "gitleaks")
        incidents.append({
            "event_type": "secret_exposed", "source": "gitleaks",
            "severity": ml["severity"], "repo": metadata.get("repo", project),
            "mitre_id": ml["mitre"]["id"],
            "details": json.dumps({
                "rule_id": f.get("RuleID",""), "file": f.get("File",""),
                "line": f.get("StartLine",0), "entropy": f.get("Entropy",0),
                "secret_hint": (f.get("Secret","")[:10]+"***") if f.get("Secret") else "",
                "ml_score": ml["score"], "build": metadata.get("build","")
            })
        })
    return incidents

def extract_poc_url(references):
    """Extraire lien PoC depuis les références CVE (GitHub exploit, ExploitDB)."""
    poc_keywords = ["exploit", "poc", "proof-of-concept", "exploit-db", "exploitdb"]
    for ref in (references or []):
        ref_lower = ref.lower()
        if any(k in ref_lower for k in poc_keywords):
            return ref
        if "github.com" in ref_lower and any(k in ref_lower for k in ["cve-", "exploit", "rce", "poc"]):
            return ref
    return ""

def extract_cvss(vuln):
    """Extraire le score CVSS v3 depuis les données Trivy."""
    cvss_data = vuln.get("CVSS", {})
    for source in ("nvd", "ghsa", "redhat"):
        if source in cvss_data:
            v3 = cvss_data[source].get("V3Score")
            if v3:
                return round(float(v3), 1)
    return None

def classify_vuln_type(title, description):
    """Classifier le type de vulnérabilité."""
    text = (title + " " + description).lower()
    if any(k in text for k in ["remote code exec", "rce", "arbitrary code", "code execution"]):
        return "RCE"
    if any(k in text for k in ["sql inject", "sqli"]):
        return "SQLi"
    if any(k in text for k in ["privilege escal", "privesc", "local privilege"]):
        return "PrivEsc"
    if any(k in text for k in ["path traversal", "directory traversal", "lfi", "rfi"]):
        return "PathTraversal"
    if any(k in text for k in ["xxe", "xml external"]):
        return "XXE"
    if any(k in text for k in ["ssrf", "server-side request"]):
        return "SSRF"
    if any(k in text for k in ["xss", "cross-site script"]):
        return "XSS"
    if any(k in text for k in ["deserializ", "deserialization"]):
        return "Deserialization"
    if any(k in text for k in ["auth bypass", "authentication bypass", "broken auth"]):
        return "AuthBypass"
    if any(k in text for k in ["denial of service", "dos", "infinite loop"]):
        return "DoS"
    if any(k in text for k in ["buffer overflow", "heap overflow", "stack overflow"]):
        return "MemoryCorruption"
    return "CVE"

def normalize_trivy(report, project, metadata):
    incidents = []
    for result in report.get("Results",[]):
        target = result.get("Target", "")
        for vuln in (result.get("Vulnerabilities") or []):
            ml = ml_score(vuln, "trivy")
            references = vuln.get("References", [])
            poc_url    = extract_poc_url(references)
            cvss_score = extract_cvss(vuln)
            title       = vuln.get("Title", "")[:120]
            description = vuln.get("Description", "")[:300]
            vuln_type   = classify_vuln_type(title, description)

            # Lien NVD direct
            cve_id    = vuln.get("VulnerabilityID", "")
            nvd_url   = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else ""

            incidents.append({
                "event_type": "cve_dependency", "source": "trivy",
                "severity": ml["severity"], "repo": metadata.get("repo", project),
                "mitre_id": ml["mitre"]["id"],
                "details": json.dumps({
                    "cve_id":       cve_id,
                    "package":      vuln.get("PkgName",""),
                    "target":       target,
                    "version":      vuln.get("InstalledVersion",""),
                    "fixed_version": vuln.get("FixedVersion",""),
                    "title":        title,
                    "description":  description,
                    "cvss_score":   cvss_score,
                    "vuln_type":    vuln_type,
                    "poc_url":      poc_url,
                    "nvd_url":      nvd_url,
                    "references":   references[:5],
                    "ml_score":     ml["score"],
                    "build":        metadata.get("build",""),
                    "repo":         metadata.get("repo", project),
                })
            })
    return incidents

def normalize_owasp(report, project, metadata):
    incidents = []
    for dep in report.get("dependencies",[]):
        for vuln in dep.get("vulnerabilities",[]):
            ml = ml_score(vuln, "owasp")
            incidents.append({
                "event_type": "cve_dependency", "source": "owasp",
                "severity": ml["severity"], "repo": metadata.get("repo", project),
                "mitre_id": ml["mitre"]["id"],
                "details": json.dumps({
                    "cve_id": vuln.get("name",""), "package": dep.get("fileName",""),
                    "description": vuln.get("description","")[:100],
                    "ml_score": ml["score"], "build": metadata.get("build","")
                })
            })
    return incidents

def normalize_sonarqube(report, project, metadata):
    incidents = []
    for issue in report.get("issues",[]):
        ml = ml_score(issue, "sonarqube")
        if ml["severity"] in ("CRITICAL","HIGH","MEDIUM"):
            incidents.append({
                "event_type": "code_vulnerability", "source": "sonarqube",
                "severity": ml["severity"], "repo": metadata.get("repo", project),
                "mitre_id": ml["mitre"]["id"],
                "details": json.dumps({
                    "rule": issue.get("rule",""), "message": issue.get("message","")[:100],
                    "component": issue.get("component",""), "line": issue.get("line",0),
                    "ml_score": ml["score"], "build": metadata.get("build","")
                })
            })
    return incidents

NORMALIZERS = {
    "gitleaks": normalize_gitleaks,
    "trivy": normalize_trivy,
    "owasp": normalize_owasp,
    "sonarqube": normalize_sonarqube,
}

def insert_incident(incident):
    with get_conn() as c:
        c.execute("""
            INSERT INTO incident (event_type, source, severity, repo, mitre_id, details, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (
            incident["event_type"], incident["source"], incident["severity"],
            incident.get("repo",""), incident.get("mitre_id","T1190"),
            incident.get("details","{}"),
            datetime.datetime.now(datetime.timezone.utc).isoformat()
        ))

def process_report(tool, project, report, metadata=None):
    if metadata is None: metadata = {}
    scanner = detect_scanner(report, tool)
    normalizer = NORMALIZERS.get(scanner, lambda r,p,m: [])
    try:
        incidents = normalizer(report, project, metadata)
    except Exception as e:
        print(f"[DevSecOps] Erreur {scanner}: {e}")
        incidents = []
    stored = 0
    critical = high = medium = low = 0
    scores = []
    for inc in incidents:
        try:
            insert_incident(inc)
            stored += 1
            s = inc["severity"]
            if s=="CRITICAL": critical+=1
            elif s=="HIGH": high+=1
            elif s=="MEDIUM": medium+=1
            else: low+=1
            try:
                d = json.loads(inc.get("details","{}"))
                if "ml_score" in d: scores.append(d["ml_score"])
            except: pass
        except Exception as e:
            print(f"[DevSecOps] Erreur stockage: {e}")
    avg = sum(scores)/len(scores) if scores else 0
    mx = max(scores) if scores else 0
    risk = "CRITICAL" if critical>0 or mx>=80 else "HIGH" if high>0 or mx>=60 else "MEDIUM" if stored>0 else "LOW"
    print(f"[DevSecOps] {scanner} — {project}: {stored} findings ({critical} CRITICAL) risk={risk}")
    return {
        "scanner": scanner, "scanner_detected": "auto" if not tool else "hint",
        "project": project, "total_findings": len(incidents),
        "stored": stored, "critical": critical, "high": high, "medium": medium, "low": low,
        "ml_avg_score": round(avg,1), "ml_max_score": mx, "risk_level": risk,
        "mitre_techniques": list(set(i["mitre_id"] for i in incidents)),
        "processed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
