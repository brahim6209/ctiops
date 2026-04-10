import json, re

DETECTORS = [
    {
        "tool": "trivy",
        "check": lambda d: isinstance(d, dict) and "Results" in d and any("Vulnerabilities" in r for r in d.get("Results", []) if r),
        "parser": lambda d: {
            "findings": [
                {
                    "id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity","UNKNOWN"),
                    "package": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "title": v.get("Title",""),
                    "cvss": (v.get("CVSS") or {}).get("nvd", {}).get("V3Score") or
                            (v.get("CVSS") or {}).get("ghsa", {}).get("V3Score") or 0,
                }
                for r in d.get("Results", [])
                for v in (r.get("Vulnerabilities") or [])
            ]
        }
    },
    {
        "tool": "gitleaks",
        "check": lambda d: isinstance(d, list) and all("RuleID" in x or "ruleId" in x for x in d[:3]) if d else isinstance(d, list),
        "parser": lambda d: {
            "findings": [
                {
                    "id": x.get("RuleID", x.get("ruleId","")),
                    "rule_id": x.get("RuleID", x.get("ruleId","")),
                    "severity": "HIGH",
                    "file": x.get("File", x.get("file","")),
                    "line": x.get("StartLine", x.get("line",0)),
                    "secret": x.get("Secret","")[:20] + "...",
                    "secret_hint": (x.get("Secret","") or "")[:30],
                    "entropy": round(float(x.get("Entropy", 0) or 0), 2),
                    "description": x.get("Description", x.get("description","")),
                    "match": x.get("Match","")[:50],
                }
                for x in d
            ]
        }
    },
    {
        "tool": "sonarqube",
        "check": lambda d: isinstance(d, dict) and ("issues" in d or "hotspots" in d or "projectStatus" in d),
        "parser": lambda d: {
            "findings": [
                {
                    "id": x.get("key",""),
                    "severity": x.get("severity","UNKNOWN"),
                    "rule": x.get("rule",""),
                    "message": x.get("message",""),
                    "file": x.get("component",""),
                    "line": x.get("line",0),
                    "type": x.get("type",""),
                }
                for x in d.get("issues", [])
            ]
        }
    },
    {
        "tool": "owasp-zap",
        "check": lambda d: isinstance(d, dict) and "site" in d and any("alerts" in str(s) for s in (d.get("site") or [])),
        "parser": lambda d: {
            "findings": [
                {
                    "id": a.get("pluginid",""),
                    "severity": ["INFO","LOW","MEDIUM","HIGH","CRITICAL"][min(int(a.get("riskcode",0)),4)],
                    "name": a.get("name",""),
                    "description": a.get("desc","")[:200],
                    "solution": a.get("solution","")[:200],
                    "url": a.get("instances",[{}])[0].get("uri","") if a.get("instances") else "",
                    "cvss": float(a.get("cvssv3","0") or 0),
                }
                for site in (d.get("site") or [])
                for a in (site.get("alerts") or [])
            ]
        }
    },
    {
        "tool": "owasp",
        "check": lambda d: isinstance(d, dict) and "dependencies" in d,
        "parser": lambda d: {
            "findings": [
                {
                    "id": v.get("name",""),
                    "severity": v.get("severity","UNKNOWN"),
                    "package": dep.get("fileName",""),
                    "description": v.get("description","")[:200],
                    "cvss": v.get("cvssv3",{}).get("baseScore",0) if isinstance(v.get("cvssv3"),dict) else 0,
                }
                for dep in d.get("dependencies",[])
                for v in dep.get("vulnerabilities",[])
            ]
        }
    },
    {
        "tool": "snyk",
        "check": lambda d: isinstance(d, dict) and "vulnerabilities" in d and "packageManager" in d,
        "parser": lambda d: {
            "findings": [
                {
                    "id": v.get("id",""),
                    "severity": v.get("severity","UNKNOWN"),
                    "package": v.get("packageName",""),
                    "version": v.get("version",""),
                    "title": v.get("title",""),
                    "cvss": v.get("cvssScore",0),
                }
                for v in d.get("vulnerabilities",[])
            ]
        }
    },
    {
        "tool": "semgrep",
        "check": lambda d: isinstance(d, dict) and "results" in d and "errors" in d,
        "parser": lambda d: {
            "findings": [
                {
                    "id": r.get("check_id",""),
                    "severity": r.get("extra",{}).get("severity","UNKNOWN"),
                    "file": r.get("path",""),
                    "line": r.get("start",{}).get("line",0),
                    "message": r.get("extra",{}).get("message",""),
                    "rule": r.get("check_id",""),
                }
                for r in d.get("results",[])
            ]
        }
    },
    {
        "tool": "grype",
        "check": lambda d: isinstance(d, dict) and "matches" in d and "source" in d,
        "parser": lambda d: {
            "findings": [
                {
                    "id": m.get("vulnerability",{}).get("id",""),
                    "severity": m.get("vulnerability",{}).get("severity","UNKNOWN"),
                    "package": m.get("artifact",{}).get("name",""),
                    "version": m.get("artifact",{}).get("version",""),
                    "fixed": m.get("vulnerability",{}).get("fix",{}).get("versions",[""])[0],
                    "cvss": m.get("vulnerability",{}).get("cvss",[{}])[0].get("metrics",{}).get("baseScore",0) if m.get("vulnerability",{}).get("cvss") else 0,
                }
                for m in d.get("matches",[])
            ]
        }
    },
    {
        "tool": "checkov",
        "check": lambda d: isinstance(d, dict) and "results" in d and "passed_checks" in d.get("results",{}),
        "parser": lambda d: {
            "findings": [
                {
                    "id": c.get("check_id",""),
                    "severity": "HIGH",
                    "file": c.get("repo_file_path",""),
                    "resource": c.get("resource",""),
                    "check": c.get("check_id",""),
                    "description": c.get("check_id",""),
                }
                for c in d.get("results",{}).get("failed_checks",[])
            ]
        }
    },
]

def detect_and_parse(report: dict) -> dict:
    for detector in DETECTORS:
        try:
            if detector["check"](report):
                parsed = detector["parser"](report)
                return {
                    "tool": detector["tool"],
                    "findings": parsed.get("findings", []),
                    "total": len(parsed.get("findings", [])),
                    "detected": True
                }
        except Exception:
            continue
    return {"tool": "unknown", "findings": [], "total": 0, "detected": False}

def severity_to_int(s):
    return {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"UNKNOWN":0}.get(str(s).upper(),0)

def compute_risk(findings):
    if not findings: return "LOW"
    severities = [severity_to_int(f.get("severity","")) for f in findings]
    if any(s >= 4 for s in severities): return "CRITICAL"
    if any(s >= 3 for s in severities): return "HIGH"
    if any(s >= 2 for s in severities): return "MEDIUM"
    return "LOW"
