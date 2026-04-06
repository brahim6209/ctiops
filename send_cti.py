 
#!/usr/bin/env python3
"""
send_cti.py — Pipeline Jenkins → CTI Platform
Envoie les résultats de chaque scanner au format attendu par l'API CTI
"""

import json
import os
import sys
import requests
from datetime import datetime, timezone

# ─── Config ───────────────────────────────────────────────────────────────────
CTI_API   = os.environ.get("CTI_URL", "http://localhost:5000")
BUILD_NUM = os.environ.get("BUILD_NUMBER", "0")
BUILD_URL = os.environ.get("BUILD_URL", "")
REPO_NAME = os.environ.get("GIT_URL", "topTrucks").split("/")[-1].replace(".git", "")
BRANCH    = os.environ.get("GIT_BRANCH", "master")
COMMIT    = os.environ.get("GIT_COMMIT", "")[:8]

WORKSPACE = os.environ.get(
    "WORKSPACE",
    "/var/lib/jenkins/workspace/cti/topTrucks"
)

HEADERS = {"Content-Type": "application/json"}

# ─── MITRE mapping ─────────────────────────────────────────────────────────────
MITRE_SECRET  = "T1552.001"   # Credentials in Files
MITRE_CVE_RCE = "T1190"       # Exploit Public-Facing Application
MITRE_CVE_DEP = "T1195"       # Supply Chain Compromise
MITRE_SAST    = "T1059"       # Command & Scripting Interpreter

# ─── Severity helper ───────────────────────────────────────────────────────────
def cvss_to_severity(score):
    if score is None:
        return "MEDIUM"
    score = float(score)
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

def nvd_severity(sev):
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return s
    return "MEDIUM"

# ─── Post to CTI ──────────────────────────────────────────────────────────────
def post_incident(payload: dict):
    payload["build"]  = BUILD_NUM
    payload["repo"]   = REPO_NAME
    payload["branch"] = BRANCH
    payload["commit"] = COMMIT
    try:
        r = requests.post(
            f"{CTI_API}/api/v1/incidents",
            json=payload,
            headers=HEADERS,
            timeout=10
        )
        return r.status_code in (200, 201)
    except Exception as e:
        print(f"    [WARN] POST failed: {e}")
        return False

# ─── GitLeaks ─────────────────────────────────────────────────────────────────
def send_gitleaks():
    path = os.path.join(WORKSPACE, "gitleaks-report.json")
    if not os.path.exists(path):
        print("gitleaks: rapport absent")
        return 0

    with open(path) as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        findings = []

    count = 0
    for leak in findings:
        rule_id     = leak.get("RuleID", "unknown")
        file_path   = leak.get("File", "")
        secret_hint = (leak.get("Secret", "") or "")[:20] + "***"
        entropy     = round(leak.get("Entropy", 0.0), 2)
        line        = leak.get("StartLine", 0)
        author      = leak.get("Author", "")
        email       = leak.get("Email", "")
        description = leak.get("Description", rule_id)

        severity = "CRITICAL" if entropy > 4.5 else "HIGH"

        details = {
            "rule_id":     rule_id,
            "file":        file_path,
            "line":        line,
            "secret_hint": secret_hint,
            "entropy":     entropy,
            "author":      author,
            "email":       email,
            "description": description,
            "build":       BUILD_NUM,
            "repo":        REPO_NAME,
            "branch":      BRANCH,
        }

        ok = post_incident({
            "source":     "gitleaks",
            "event_type": "secret_detected",
            "severity":   severity,
            "mitre_id":   MITRE_SECRET,
            "details":    json.dumps(details),
        })
        if ok:
            count += 1

    print(f"gitleaks: scanner=gitleaks findings={count} risk={'CRITICAL' if count > 0 else 'LOW'}")
    return count

# ─── Trivy ────────────────────────────────────────────────────────────────────
def send_trivy():
    path = os.path.join(WORKSPACE, "trivy-report.json")
    if not os.path.exists(path):
        print("trivy: rapport absent")
        return 0

    with open(path) as f:
        report = json.load(f)

    results = report.get("Results", [])
    count   = 0
    crit    = 0

    for result in results:
        target = result.get("Target", "")
        for vuln in (result.get("Vulnerabilities") or []):
            cve_id      = vuln.get("VulnerabilityID", "")
            pkg_name    = vuln.get("PkgName", "")
            installed   = vuln.get("InstalledVersion", "")
            fixed       = vuln.get("FixedVersion", "")
            severity    = nvd_severity(vuln.get("Severity", "MEDIUM"))
            title       = vuln.get("Title", "")
            description = vuln.get("Description", "")[:300]
            cvss_score  = None
            references  = vuln.get("References", [])
            poc_url     = ""

            # Extract CVSS
            cvss_data = vuln.get("CVSS", {})
            for source in ("nvd", "ghsa"):
                if source in cvss_data:
                    v3 = cvss_data[source].get("V3Score")
                    if v3:
                        cvss_score = v3
                        severity   = cvss_to_severity(v3)
                        break

            # PoC link from references (GitHub / ExploitDB)
            for ref in references:
                if "exploit" in ref.lower() or "github.com/exploit" in ref.lower() or "exploit-db" in ref.lower():
                    poc_url = ref
                    break

            # MITRE mapping
            mitre = MITRE_CVE_RCE
            desc_lower = (title + description).lower()
            if any(k in desc_lower for k in ["supply", "dependency", "package"]):
                mitre = MITRE_CVE_DEP

            if severity == "CRITICAL":
                crit += 1

            details = {
                "cve_id":       cve_id,
                "package":      pkg_name,
                "target":       target,
                "version":      installed,
                "fixed_version": fixed,
                "cvss_score":   cvss_score,
                "title":        title,
                "description":  description,
                "poc_url":      poc_url,
                "references":   references[:3],
                "vuln_type":    "CVE",
                "build":        BUILD_NUM,
                "repo":         REPO_NAME,
            }

            ok = post_incident({
                "source":     "trivy",
                "event_type": "cve_detected",
                "severity":   severity,
                "mitre_id":   mitre,
                "details":    json.dumps(details),
            })
            if ok:
                count += 1

    print(f"trivy: scanner=trivy findings={count} risk={'CRITICAL' if crit > 0 else 'HIGH' if count > 0 else 'LOW'}")
    return count

# ─── OWASP ────────────────────────────────────────────────────────────────────
def send_owasp():
    # OWASP report can be in different locations
    candidates = [
        os.path.join(WORKSPACE, "owasp-report", "dependency-check-report.json"),
        os.path.join(WORKSPACE, "owasp-report.json"),
    ]

    report_path = None
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 100:
            report_path = c
            break

    if not report_path:
        print("owasp: scanner=owasp findings=0 risk=LOW")
        return 0

    with open(report_path) as f:
        report = json.load(f)

    deps  = report.get("dependencies", [])
    count = 0
    crit  = 0

    for dep in deps:
        vulns = dep.get("vulnerabilities", [])
        for vuln in vulns:
            cve_id      = vuln.get("name", "")
            severity    = nvd_severity(vuln.get("severity", "MEDIUM"))
            description = vuln.get("description", "")[:300]
            cvss_score  = None

            # CVSS
            cvss_v3 = vuln.get("cvssv3", {})
            if cvss_v3:
                cvss_score = cvss_v3.get("baseScore")
                severity   = cvss_to_severity(cvss_score)

            references = [
                r.get("url", "") for r in vuln.get("references", [])
            ]
            poc_url = next((r for r in references if "exploit" in r.lower()), "")

            if severity == "CRITICAL":
                crit += 1

            details = {
                "cve_id":      cve_id,
                "package":     dep.get("fileName", ""),
                "description": description,
                "cvss_score":  cvss_score,
                "poc_url":     poc_url,
                "references":  references[:3],
                "build":       BUILD_NUM,
                "repo":        REPO_NAME,
            }

            ok = post_incident({
                "source":     "owasp",
                "event_type": "cve_dependency",
                "severity":   severity,
                "mitre_id":   MITRE_CVE_DEP,
                "details":    json.dumps(details),
            })
            if ok:
                count += 1

    print(f"owasp: scanner=owasp findings={count} risk={'CRITICAL' if crit > 0 else 'HIGH' if count > 0 else 'LOW'}")
    return count

# ─── SonarQube ────────────────────────────────────────────────────────────────
def send_sonarqube():
    SONAR_URL   = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
    SONAR_TOKEN = os.environ.get("SONAR_TOKEN", "")
    PROJECT_KEY = os.environ.get("SONAR_PROJECT_KEY", "toptrucks")

    if not SONAR_TOKEN:
        print("sonarqube: pas de token SONAR_TOKEN, skip")
        return 0

    try:
        # Fetch issues from SonarQube API
        r = requests.get(
            f"{SONAR_URL}/api/issues/search",
            params={
                "componentKeys": PROJECT_KEY,
                "severities":    "BLOCKER,CRITICAL,MAJOR",
                "statuses":      "OPEN,REOPENED",
                "ps":            100,
            },
            auth=(SONAR_TOKEN, ""),
            timeout=15
        )
        data   = r.json()
        issues = data.get("issues", [])
    except Exception as e:
        print(f"sonarqube: erreur API ({e}), skip")
        return 0

    count = 0
    for issue in issues:
        sev_map  = {"BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM"}
        severity = sev_map.get(issue.get("severity", "MAJOR"), "MEDIUM")
        rule_id  = issue.get("rule", "")
        message  = issue.get("message", "")
        file_path = issue.get("component", "").replace(f"{PROJECT_KEY}:", "")

        details = {
            "rule_id":   rule_id,
            "file":      file_path,
            "message":   message,
            "type":      issue.get("type", ""),
            "effort":    issue.get("effort", ""),
            "build":     BUILD_NUM,
            "repo":      REPO_NAME,
        }

        ok = post_incident({
            "source":     "sonarqube",
            "event_type": "sast_issue",
            "severity":   severity,
            "mitre_id":   MITRE_SAST,
            "details":    json.dumps(details),
        })
        if ok:
            count += 1

    print(f"sonarqube: scanner=sonarqube findings={count}")
    return count

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'='*50}")
    print(f"CTI Platform — Build #{BUILD_NUM} | Repo: {REPO_NAME} | Branch: {BRANCH}")
    print(f"{'='*50}")

    total = 0
    total += send_gitleaks()
    total += send_trivy()
    total += send_owasp()
    total += send_sonarqube()

    print(f"\n=== Tous rapports envoyes === Total findings: {total} ===")
    sys.exit(0)


