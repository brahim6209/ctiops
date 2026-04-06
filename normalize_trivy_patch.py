
# Ce script patche devsecops_collector.py
# Remplace normalize_trivy par la version enrichie avec poc_url + cvss + description

import re

path = "/home/br1kx/cti/ctiops/devsecops_collector.py"
content = open(path).read()

old = '''def normalize_trivy(report, project, metadata):
    incidents = []
    for result in report.get("Results",[]):
        for vuln in (result.get("Vulnerabilities") or []):
            ml = ml_score(vuln, "trivy")
            incidents.append({
                "event_type": "cve_dependency", "source": "trivy",
                "severity": ml["severity"], "repo": metadata.get("repo", project),
                "mitre_id": ml["mitre"]["id"],
                "details": json.dumps({
                    "cve_id": vuln.get("VulnerabilityID",""),
                    "package": vuln.get("PkgName",""),
                    "version": vuln.get("InstalledVersion",""),
                    "fixed": vuln.get("FixedVersion",""),
                    "title": vuln.get("Title","")[:100],
                    "ml_score": ml["score"], "build": metadata.get("build","")
                })
            })
    return incidents'''

new = '''def extract_poc_url(references):
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
    return incidents'''

if old in content:
    content = content.replace(old, new)
    open(path, 'w').write(content)
    print("✅ normalize_trivy patché avec succès")
    print("   → poc_url, cvss_score, vuln_type, description, nvd_url ajoutés")
else:
    print("❌ Pattern non trouvé — vérifiez le fichier manuellement")


