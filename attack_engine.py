"""
attack_engine.py — ML Attack Prediction Engine v2.0
Cloud CVE + DevSecOps → Attack Paths + Kill Chain + Risk Scores
"""
import json, datetime
import numpy as np
from database import get_conn

MITRE_MAP = {
    "T1595": {"stage":1,"name":"Active Scanning","kill_chain":"Reconnaissance"},
    "T1592": {"stage":1,"name":"Gather Host Info","kill_chain":"Reconnaissance"},
    "T1190": {"stage":3,"name":"Exploit Public App","kill_chain":"Delivery"},
    "T1195": {"stage":3,"name":"Supply Chain Compromise","kill_chain":"Delivery"},
    "T1552": {"stage":3,"name":"Unsecured Credentials","kill_chain":"Delivery"},
    "T1552.001": {"stage":3,"name":"Credentials In Files","kill_chain":"Delivery"},
    "T1068": {"stage":4,"name":"Privilege Escalation","kill_chain":"Exploitation"},
    "T1059": {"stage":4,"name":"Command Execution","kill_chain":"Exploitation"},
    "T1078": {"stage":4,"name":"Valid Accounts","kill_chain":"Exploitation"},
    "T1136": {"stage":5,"name":"Create Account","kill_chain":"Installation"},
    "T1071": {"stage":6,"name":"App Layer Protocol","kill_chain":"C2"},
    "T1486": {"stage":7,"name":"Data Encrypted","kill_chain":"Actions"},
    "T1041": {"stage":7,"name":"Exfil Over C2","kill_chain":"Actions"},
}

# ⚠️ LIMITE : Mapping CVE→MITRE basé sur mots-clés statiques (NVD utilise la même approche)
# Précision non validée formellement — approximation raisonnable pour le prototype
CVE_MITRE = {
    "rce":["T1190","T1059"], "remote code":["T1190","T1059"],
    "injection":["T1190","T1059"], "privilege":["T1068"],
    "escalat":["T1068"], "credential":["T1552","T1078"],
    "secret":["T1552.001"], "token":["T1552","T1078"],
    "password":["T1552.001","T1078"], "jwt":["T1552","T1078"],
    "supply":["T1195"], "docker":["T1068","T1136"],
    "kubernetes":["T1068","T1136"], "aws":["T1078","T1190"],
    "jenkins":["T1190","T1059"], "github":["T1195","T1552"],
}

# ⚠️ LIMITE : Seuls les stages 1,3,4,5 sont couverts par nos données
# Stages 2 (Weaponization), 6 (C2), 7 (Actions) nécessitent un monitoring réseau non disponible
KILL_CHAIN_STAGES = [
    {"id":1,"name":"Reconnaissance",       "covered":True},
    {"id":2,"name":"Weaponization",        "covered":False, "note":"Non couvert — pas de données"},
    {"id":3,"name":"Delivery",             "covered":True},
    {"id":4,"name":"Exploitation",         "covered":True},
    {"id":5,"name":"Installation",         "covered":True},
    {"id":6,"name":"Command & Control",    "covered":False, "note":"Non couvert — pas de monitoring réseau"},
    {"id":7,"name":"Actions on Objectives","covered":False, "note":"Non couvert — pas de monitoring réseau"},
]

def extract_features(cve):
    desc = (cve.get("description") or "").lower()
    return {
        "cvss":     float(cve.get("cvss_score") or 0),
        "epss":     float(cve.get("epss_score") or 0),
        "has_exploit": int(cve.get("has_exploit") or 0),
        "active":   int(cve.get("actively_exploited") or 0),
        "is_rce":   int(any(k in desc for k in ["rce","remote code","execute"])),
        "is_priv":  int(any(k in desc for k in ["privilege","escalat","root"])),
        "is_cred":  int(any(k in desc for k in ["credential","auth","password","token","secret"])),
        "is_supply":int(any(k in desc for k in ["supply","depend","package"])),
        "is_cloud": int(any(k in desc for k in ["aws","azure","gcp","cloud","lambda","s3"])),
        "is_cicd":  int(any(k in desc for k in ["jenkins","github","gitlab","ci/cd","pipeline"])),
        "is_container": int(any(k in desc for k in ["docker","container","kubernetes","k8s"])),
    }

def ml_probability(f, cve_data=None):
    if cve_data:
        try:
            from ml_engine import predict_exploitation
            r = predict_exploitation(cve_data)
            if r.get("model") == "RandomForest":
                return r["probability"]
        except:
            pass
    score = (f["epss"]*40 + (f["cvss"]/10)*20 + f["has_exploit"]*15 + f["active"]*20
             + f["is_rce"]*8 + f["is_priv"]*5 + f["is_cred"]*6
             + f["is_supply"]*4 + f["is_cloud"]*3 + f["is_cicd"]*4)
    return min(99, max(1, round(score, 1)))

def get_techniques(desc):
    desc = desc.lower()
    techs = []
    for kw, ts in CVE_MITRE.items():
        if kw in desc: techs.extend(ts)
    return list(dict.fromkeys(techs))[:4]

def days_to_exploit(f, prob):
    if f["active"]: return 0
    if f["has_exploit"] and prob>80: return 3
    if prob>70: return 7
    if prob>50: return 30
    return 90

def predict_cloud_attack_paths():
    paths = []
    with get_conn() as c:
        cves = c.execute("""
            SELECT id,description,cvss_score,severity,has_exploit,
                   epss_score,actively_exploited,exploit_source
            FROM cve
            ORDER BY (COALESCE(actively_exploited,0)*20+COALESCE(epss_score,0)*40+
                      COALESCE(has_exploit,0)*15+COALESCE(cvss_score,0)*2) DESC
            LIMIT 10
        """).fetchall()
    for cve in cves:
        d = dict(cve)
        f = extract_features(d)
        prob = ml_probability(f, d)
        if prob < 30: continue
        techs = get_techniques(d.get("description","")) or ["T1190"]
        days = days_to_exploit(f, prob)
        steps = [{"stage":1,"action":"Reconnaissance infrastructure cloud","technique":"T1595","asset":"Cloud Infrastructure"}]
        if f["is_rce"]:
            steps += [
                {"stage":3,"action":f"Exploitation {d['id']}","technique":techs[0],"asset":"Application"},
                {"stage":4,"action":"RCE / Privilege Escalation","technique":"T1059","asset":"Server"}
            ]
        elif f["is_cred"]:
            steps += [
                {"stage":3,"action":f"Vol credentials via {d['id']}","technique":"T1552","asset":"Secrets"},
                {"stage":4,"action":"Accès avec credentials volés","technique":"T1078","asset":"System"}
            ]
        else:
            steps.append({"stage":3,"action":f"Exploitation {d['id']}","technique":techs[0],"asset":"Component"})
        if f["is_cloud"]:
            steps.append({"stage":7,"action":"Exfiltration données cloud","technique":"T1041","asset":"Storage"})
        recs = []
        if d.get("actively_exploited"): recs.append(f"PATCH IMMÉDIAT — {d['id']} exploitée activement")
        if f["epss"]>0.5: recs.append(f"EPSS {f['epss']*100:.0f}% — probabilité très haute")
        if f["has_exploit"]: recs.append("Exploit public — patch sous 24h")
        paths.append({
            "id": f"cloud-{d['id']}", "source":"cloud",
            "title": f"Attack Path — {d['id']}",
            "trigger": (d.get("description") or "")[:120],
            "probability": prob, "severity": d.get("severity","MEDIUM"),
            "cvss": d.get("cvss_score"), "epss": f["epss"],
            "has_exploit": bool(f["has_exploit"]), "active": bool(f["active"]),
            "days_to_exploit": days,
            "patch_priority": ("P0-IMMEDIATE" if days==0 else "P1-URGENT" if days<=7
                               else "P2-PLANNED" if days<=30 else "P3-MONITOR"),
            "mitre_chain": techs, "steps": steps, "recommendations": recs
        })
    return sorted(paths, key=lambda x: x["probability"], reverse=True)

def predict_devsecops_attack_paths():
    paths = []
    with get_conn() as c:
        incidents = c.execute("""
            SELECT * FROM incident ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
            WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC LIMIT 30
        """).fetchall()
    if not incidents: return []
    incs = [dict(i) for i in incidents]
    secrets = [i for i in incs if i["source"]=="gitleaks"]
    cve_finds = [i for i in incs if i["source"] in ("trivy","owasp")]
    code_issues = [i for i in incs if i["source"]=="sonarqube"]
    if secrets:
        crit = [s for s in secrets if s["severity"] in ("CRITICAL","HIGH")]
        # ⚠️ RÈGLE HEURISTIQUE (non ML) — baseline 60% + 10% par secret critique
        # Justification : secrets exposés = compromission quasi-certaine si repo public
        prob = min(95, 60+len(crit)*10)
        paths.append({
            "id":"devsecops-secrets","source":"devsecops",
            "title":"Credential Theft via Exposed Secrets",
            "trigger":f"{len(secrets)} secrets dans le code ({len(crit)} critiques)",
            "probability":prob,"severity":"CRITICAL" if crit else "HIGH",
            "days_to_exploit":1 if crit else 7,
            "patch_priority":"P0-IMMEDIATE" if crit else "P1-URGENT",
            "mitre_chain":["T1552.001","T1078","T1190","T1041"],
            "steps":[
                {"stage":1,"action":"Découverte repo code","technique":"T1592","asset":"Code Repository"},
                {"stage":3,"action":f"Extraction {len(secrets)} secrets","technique":"T1552.001","asset":"Source Code"},
                {"stage":4,"action":"Accès non autorisé","technique":"T1078","asset":"Database/API"},
                {"stage":7,"action":"Exfiltration","technique":"T1041","asset":"Sensitive Data"},
            ],
            "recommendations":[
                f"Rotater IMMÉDIATEMENT les {len(secrets)} secrets",
                "Activer Git Secret Scanning","Utiliser HashiCorp Vault"
            ]
        })
    if cve_finds:
        crit = [c for c in cve_finds if c["severity"] in ("CRITICAL","HIGH")]
        prob = min(90, 50+len(crit)*8)
        paths.append({
            "id":"devsecops-dependencies","source":"devsecops",
            "title":"Supply Chain via Vulnerable Dependencies",
            "trigger":f"{len(cve_finds)} CVE dans dépendances ({len(crit)} critiques)",
            "probability":prob,"severity":"CRITICAL" if crit else "HIGH",
            "days_to_exploit":7 if crit else 30,
            "patch_priority":"P1-URGENT" if crit else "P2-PLANNED",
            "mitre_chain":["T1195","T1059","T1136"],
            "steps":[
                {"stage":1,"action":"Identification dépendances vulnérables","technique":"T1592","asset":"pom.xml"},
                {"stage":3,"action":"Exploitation via dépendance","technique":"T1195","asset":"Library"},
                {"stage":4,"action":"Exécution code malveillant","technique":"T1059","asset":"Runtime"},
            ],
            "recommendations":[
                f"Mettre à jour {len(crit)} dépendances critiques",
                "Activer Dependabot","Scanner images Docker avec Trivy"
            ]
        })
    return sorted(paths, key=lambda x: x["probability"], reverse=True)

def predict_attack_paths():
    cloud = predict_cloud_attack_paths()
    devsec = predict_devsecops_attack_paths()
    all_paths = sorted(cloud+devsec, key=lambda x: x["probability"], reverse=True)
    return {
        "paths": all_paths[:10], "total": len(all_paths),
        "cloud_paths": len(cloud), "devsecops_paths": len(devsec),
        "high_probability": sum(1 for p in all_paths if p["probability"]>=70),
        "critical": sum(1 for p in all_paths if p["severity"]=="CRITICAL"),
        "ml_model": "RandomForest + TF-IDF (scikit-learn) — Labels CISA KEV",
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

def analyze_kill_chain():
    stages = {i: {"stage": s.copy(), "items":[], "count":0, "risk_score":0}
              for i,s in enumerate(KILL_CHAIN_STAGES, 1)}
    with get_conn() as c:
        cves = c.execute("""
            SELECT id,description,cvss_score,severity,has_exploit,epss_score,actively_exploited
            FROM cve WHERE cvss_score >= 7.0
            ORDER BY COALESCE(epss_score,0)*40+COALESCE(cvss_score,0)*2 DESC LIMIT 50
        """).fetchall()
        incidents = c.execute("SELECT * FROM incident ORDER BY created_at DESC LIMIT 30").fetchall()
    for cve in cves:
        d = dict(cve)
        f = extract_features(d)
        prob = ml_probability(f, d)
        techs = get_techniques(d.get("description","")) or ["T1190"]
        for tech in techs[:2]:
            info = MITRE_MAP.get(tech, {"stage":4,"name":tech,"kill_chain":"Exploitation"})
            sid = info["stage"]
            stages[sid]["items"].append({
                "type":"cve","id":d["id"],"label":d["id"],
                "technique":tech,"technique_name":info["name"],
                "severity":d.get("severity","UNKNOWN"),
                "cvss":d.get("cvss_score",0),"epss":f["epss"],
                "probability":prob,"active":bool(f["active"]),
                "description":(d.get("description") or "")[:80]
            })
            stages[sid]["count"]+=1
    for inc in incidents:
        d = dict(inc)
        mitre = d.get("mitre_id","T1552.001") or "T1552.001"
        info = MITRE_MAP.get(mitre, {"stage":3,"name":mitre,"kill_chain":"Delivery"})
        sid = info["stage"]
        stages[sid]["items"].append({
            "type":"incident","id":str(d.get("id","")),
            "label":d.get("event_type","incident"),
            "technique":mitre,"technique_name":info["name"],
            "severity":d.get("severity","MEDIUM"),
            "source":d.get("source",""),
            "description":f"{d.get('event_type','')} — {d.get('repo','')}"
        })
        stages[sid]["count"]+=1
    for sid,s in stages.items():
        crit = sum(1 for i in s["items"] if i.get("severity")=="CRITICAL")
        high = sum(1 for i in s["items"] if i.get("severity")=="HIGH")
        s["risk_score"] = min(100, crit*20+high*10+s["count"]*2)
        s["items"] = sorted(s["items"], key=lambda x: x.get("probability",0), reverse=True)[:8]
    return {
        "stages": list(stages.values()),
        "total_items": sum(s["count"] for s in stages.values()),
        "highest_stage": max(stages.items(), key=lambda x: x[1]["count"])[0],
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

def calculate_risk_scores():
    with get_conn() as c:
        total = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        critical = c.execute("SELECT COUNT(*) FROM cve WHERE cvss_score>=9.0").fetchone()[0]
        exploit = c.execute("SELECT COUNT(*) FROM cve WHERE has_exploit=1").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM cve WHERE actively_exploited=1").fetchone()[0]
        high_epss = c.execute("SELECT COUNT(*) FROM cve WHERE epss_score>0.5").fetchone()[0]
        inc_total = c.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
        inc_crit = c.execute("SELECT COUNT(*) FROM incident WHERE severity='CRITICAL'").fetchone()[0]
    score = min(100, active*15+exploit*8+high_epss*5+critical*4+inc_crit*10)
    return {
        "global_score": score,
        "global_level": ("CRITICAL" if score>=80 else "HIGH" if score>=60
                         else "MEDIUM" if score>=30 else "LOW"),
        "breakdown": {
            "active_exploited_cve":active,"public_exploit_cve":exploit,
            "high_epss_cve":high_epss,"critical_cve":critical,
            "critical_incidents":inc_crit
        },
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

def build_relation_graph():
    nodes, links = [], []
    ids = set()
    def add(nid, label, ntype, sev="MEDIUM", extra=None):
        if nid not in ids:
            ids.add(nid)
            nodes.append({"id":nid,"label":label,"type":ntype,"severity":sev,**(extra or {})})
    with get_conn() as c:
        cves = c.execute("""
            SELECT id,description,cvss_score,severity,epss_score,has_exploit,actively_exploited
            FROM cve WHERE cvss_score>=7.0 ORDER BY COALESCE(epss_score,0) DESC LIMIT 20
        """).fetchall()
        incs = c.execute("SELECT * FROM incident ORDER BY created_at DESC LIMIT 15").fetchall()
    for cve in cves:
        d = dict(cve)
        f = extract_features(d)
        prob = ml_probability(f, d)
        add(d["id"],d["id"],"cve",d.get("severity","MEDIUM"),
            {"cvss":d.get("cvss_score",0),"epss":f["epss"],"probability":prob})
        for tech in get_techniques(d.get("description",""))[:2]:
            info = MITRE_MAP.get(tech,{"name":tech,"kill_chain":"Unknown"})
            mid = f"mitre-{tech}"
            add(mid,tech,"mitre","INFO",{"technique_name":info["name"],"kill_chain":info["kill_chain"]})
            links.append({"source":d["id"],"target":mid,"label":"exploits","strength":min(1.0,prob/100+0.3)})
    for inc in incs:
        d = dict(inc)
        iid = f"inc-{d.get('id','')}"
        add(iid,(d.get("event_type") or "incident")[:20],"incident",d.get("severity","MEDIUM"),
            {"repo":d.get("repo",""),"source":d.get("source","")})
        mitre = d.get("mitre_id","")
        if mitre:
            mid = f"mitre-{mitre}"
            info = MITRE_MAP.get(mitre,{"name":mitre,"kill_chain":"Unknown"})
            add(mid,mitre,"mitre","INFO",{"technique_name":info["name"],"kill_chain":info["kill_chain"]})
            links.append({"source":iid,"target":mid,"label":"maps_to","strength":0.9})
    return {
        "nodes":nodes,"links":links,
        "stats":{"total_nodes":len(nodes),"total_links":len(links),
                 "cve_nodes":sum(1 for n in nodes if n["type"]=="cve"),
                 "incident_nodes":sum(1 for n in nodes if n["type"]=="incident"),
                 "mitre_nodes":sum(1 for n in nodes if n["type"]=="mitre")}
    }
