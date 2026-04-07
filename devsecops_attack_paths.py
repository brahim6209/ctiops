"""
Attack paths dynamiques par build — 100% générique.
Supporte : GitLeaks, Trivy, OWASP, SonarQube, custom.
"""
import json
from database import get_conn
from ml_attack_predictor import extract_build_features, predict_exploitation_probability

def parse_details(inc):
    try:
        return json.loads(inc.get('details') or '{}')
    except:
        return {}

def get_build_incidents(build: str):
    with get_conn() as c:
        rows = c.execute("""
            SELECT * FROM incident
            WHERE json_extract(details,'$.build')=?
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC
        """, (str(build),)).fetchall()
    return [dict(r) for r in rows]

def get_enriched_cves(build: str):
    with get_conn() as c:
        rows = c.execute("""
            SELECT i.severity, i.mitre_id,
                   json_extract(i.details,'$.cve_id') as cve_id,
                   json_extract(i.details,'$.package') as package,
                   json_extract(i.details,'$.fixed_version') as fixed_version,
                   c.cvss_score, c.epss_score, c.reality_score,
                   c.actively_exploited, c.attack_type,
                   c.has_exploit, c.description
            FROM incident i
            LEFT JOIN cve c ON json_extract(i.details,'$.cve_id') = c.id
            WHERE i.source IN ('trivy','owasp')
            AND json_extract(i.details,'$.build')=?
            ORDER BY COALESCE(c.reality_score,0) DESC
        """, (str(build),)).fetchall()
    return [dict(r) for r in rows]

# ── MITRE technique par type de scanner ──────────────────────
SCANNER_MITRE = {
    'gitleaks'  : {'default': 'T1552.001', 'label': 'Credentials In Files'},
    'trivy'     : {'default': 'T1195',     'label': 'Supply Chain Compromise'},
    'owasp'     : {'default': 'T1190',     'label': 'Exploit Public-Facing App'},
    'sonarqube' : {'default': 'T1059',     'label': 'Command & Scripting Interpreter'},
    'custom'    : {'default': 'T1190',     'label': 'Exploit Public-Facing App'},
}

# ── Sévérité → probabilité de base ────────────────────────────
SEV_PROB = {'CRITICAL': 30, 'HIGH': 15, 'MEDIUM': 7, 'LOW': 2}

def compute_base_prob(incidents):
    """Calcul générique de probabilité basé sur les incidents."""
    prob = 0
    for inc in incidents:
        prob += SEV_PROB.get(inc.get('severity','LOW'), 2)
    return min(95, prob)

def build_generic_steps(scanner, incidents, enriched_map=None):
    """Générer les étapes d'attaque pour n'importe quel scanner."""
    steps = []
    mitre_info = SCANNER_MITRE.get(scanner, SCANNER_MITRE['custom'])
    crit = [i for i in incidents if i['severity'] in ('CRITICAL','HIGH')]

    steps.append({
        "stage": 1,
        "action": f"Découverte via {scanner.upper()} findings",
        "technique": "T1592",
        "asset": "Target Application",
        "detail": f"{len(incidents)} findings détectés ({len(crit)} CRITICAL/HIGH)"
    })

    # Étapes spécifiques par scanner
    if scanner == 'gitleaks':
        secret_types = {}
        for i in incidents:
            d = parse_details(i)
            rule = d.get('rule_id', 'generic')
            secret_types[rule] = secret_types.get(rule, 0) + 1
        for rule, count in list(secret_types.items())[:3]:
            steps.append({
                "stage": len(steps)+1,
                "action": f"Extraction secret — {rule} ({count}x)",
                "technique": "T1552.001", "asset": "Config / Source files",
                "detail": f"Credential exposé dans le code source"
            })
        steps.append({"stage": len(steps)+1, "action": "Authentification illégitime",
                      "technique": "T1078", "asset": "Protected Resources",
                      "detail": "Usage des credentials volés"})

    elif scanner in ('trivy', 'owasp'):
        if enriched_map:
            top = sorted(enriched_map, key=lambda x: x.get('reality_score') or 0, reverse=True)[:3]
            for cve in top:
                cve_id = cve.get('cve_id','CVE-????')
                at     = cve.get('attack_type') or 'CVE'
                rs     = cve.get('reality_score') or 0
                kev    = " [CISA KEV]" if cve.get('actively_exploited') else ""
                steps.append({
                    "stage": len(steps)+1,
                    "action": f"Exploitation {cve_id} ({at}){kev}",
                    "technique": cve.get('mitre_id') or mitre_info['default'],
                    "asset": (cve.get('package') or '').split(':')[-1] or 'Library',
                    "detail": f"Reality Score: {rs}/100"
                })
        steps.append({"stage": len(steps)+1, "action": "Exécution de code arbitraire",
                      "technique": "T1059", "asset": "Application Runtime",
                      "detail": "RCE via composant vulnérable"})

    elif scanner == 'sonarqube':
        issue_types = {}
        for i in incidents:
            d = parse_details(i)
            rule = d.get('rule_id', i.get('event_type','issue'))
            issue_types[rule] = issue_types.get(rule, 0) + 1
        for rule, count in list(issue_types.items())[:3]:
            steps.append({
                "stage": len(steps)+1,
                "action": f"Exploitation faille code — {rule}",
                "technique": mitre_info['default'],
                "asset": "Source Code",
                "detail": f"Défaut de sécurité dans le code ({count}x)"
            })

    else:  # custom / unknown scanner
        for inc in crit[:3]:
            d = parse_details(inc)
            steps.append({
                "stage": len(steps)+1,
                "action": f"Exploitation — {inc.get('event_type','Finding')}",
                "technique": inc.get('mitre_id') or mitre_info['default'],
                "asset": d.get('target') or d.get('file') or 'Target',
                "detail": f"Severity: {inc.get('severity')}"
            })

    # Étape finale commune
    steps.append({
        "stage": len(steps)+1,
        "action": "Impact — Exfiltration / Persistance / Ransomware",
        "technique": "T1041",
        "asset": "Infrastructure complète",
        "detail": "Exploitation complète de la surface d'attaque"
    })

    return steps

def build_recommendations(scanner, incidents, enriched_map=None):
    """Recommandations génériques par scanner."""
    crit = [i for i in incidents if i['severity'] in ('CRITICAL','HIGH')]
    recs = []

    if scanner == 'gitleaks':
        recs.append(f"Rotation immédiate de {len(incidents)} secrets exposés")
        recs.append("Ajouter GitLeaks en pre-commit hook")
        recs.append("Utiliser un gestionnaire de secrets (Vault, AWS SM, Azure KV)")
        recs.append("Révoquer et regénérer tous les tokens/API keys")

    elif scanner in ('trivy','owasp'):
        recs.append(f"Mettre à jour {len(crit)} dépendances CRITICAL/HIGH")
        if enriched_map:
            kev = [c for c in enriched_map if c.get('actively_exploited')]
            for k in kev[:3]:
                fix = k.get('fixed_version') or 'Pas de fix'
                recs.append(f"CISA KEV: {k.get('cve_id')} → {fix}")
        recs.append("Intégrer le scanner comme gate CI/CD (bloquer le build si CRITICAL)")
        recs.append("Activer Dependabot / Renovate pour mises à jour automatiques")

    elif scanner == 'sonarqube':
        recs.append(f"Corriger {len(crit)} code issues CRITICAL/HIGH")
        recs.append("Configurer Quality Gate SonarQube (bloquer si CRITICAL)")
        recs.append("Former les développeurs aux bonnes pratiques OWASP Top 10")

    else:
        recs.append(f"Traiter {len(crit)} findings CRITICAL/HIGH en priorité")
        recs.append("Intégrer les résultats dans le processus de code review")

    return recs

def predict_build_attack_paths(build: str):
    incs     = get_build_incidents(build)
    if not incs:
        return []

    enriched = get_enriched_cves(build)
    repo     = next((i.get('repo','') for i in incs if i.get('repo')), 'Unknown')

    # Grouper par scanner
    scanners = {}
    for i in incs:
        src = i.get('source','custom')
        if src not in scanners:
            scanners[src] = []
        scanners[src].append(i)

    # ── ML Prediction globale du build ──────────────────────
    build_features = extract_build_features(build)
    ml_result      = predict_exploitation_probability(build_features)
    ml_prob        = ml_result['probability']
    ml_confidence  = ml_result['confidence']
    ml_features    = ml_result['contributing_features']

    paths = []

    # ── Un path par scanner ───────────────────────────────────
    for scanner, scanner_incs in scanners.items():
        crit   = [i for i in scanner_incs if i['severity'] in ('CRITICAL','HIGH')]
        if not crit:
            continue  # Ignorer si aucun CRITICAL/HIGH

        mitre_info = SCANNER_MITRE.get(scanner, SCANNER_MITRE['custom'])
        enriched_for_scanner = enriched if scanner in ('trivy','owasp') else None

        # Probabilité ML (Random Forest) + ajustement par scanner
        scanner_weight = {
            'gitleaks': 0.90, 'trivy': 1.0,
            'owasp': 0.95, 'sonarqube': 0.75
        }.get(scanner, 0.80)
        prob = min(97, int(ml_prob * scanner_weight))

        sev = 'CRITICAL' if any(i['severity']=='CRITICAL' for i in scanner_incs) else 'HIGH'
        days = 1 if sev=='CRITICAL' else 7

        # Construire MITRE chain dynamiquement
        mitre_chain = [mitre_info['default']]
        if scanner == 'gitleaks':
            mitre_chain = ['T1552.001','T1078','T1041']
        elif scanner in ('trivy','owasp'):
            attack_types = set(c.get('attack_type') for c in (enriched or []) if c.get('attack_type'))
            if 'RCE' in attack_types:
                mitre_chain = ['T1195','T1190','T1059','T1041']
            else:
                mitre_chain = ['T1195','T1190','T1041']
        elif scanner == 'sonarqube':
            mitre_chain = ['T1059','T1078','T1041']

        steps = build_generic_steps(scanner, scanner_incs, enriched_for_scanner)
        recs  = build_recommendations(scanner, scanner_incs, enriched_for_scanner)

        # Résumé du contenu
        trigger_detail = f"{len(scanner_incs)} findings ({len(crit)} CRITICAL/HIGH)"
        if scanner in ('trivy','owasp') and enriched:
            kev = [c for c in enriched if c.get('actively_exploited')]
            if kev:
                trigger_detail += f" — {len(kev)} CISA KEV"

        paths.append({
            "id": f"build{build}-{scanner}",
            "source": "devsecops",
            "build": build,
            "repo": repo,
            "scanner": scanner,
            "title": f"{scanner.upper()} — {len(scanner_incs)} findings (Build #{build})",
            "trigger": trigger_detail,
            "probability": prob,
            "severity": sev,
            "days_to_exploit": days,
            "patch_priority": "P0-IMMEDIATE" if sev=='CRITICAL' else "P1-URGENT",
            "mitre_chain": mitre_chain,
            "mitre_label": mitre_info['label'],
            "steps": steps,
            "recommendations": recs,
            "stats": {
                "total": len(scanner_incs),
                "critical": sum(1 for i in scanner_incs if i['severity']=='CRITICAL'),
                "high": sum(1 for i in scanner_incs if i['severity']=='HIGH'),
                "medium": sum(1 for i in scanner_incs if i['severity']=='MEDIUM'),
            },
            "ml_prediction": {
                "model": ml_result.get('model'),
                "raw_probability": ml_prob,
                "confidence": ml_confidence,
                "top_features": ml_features
            }
        })

    # ── Path combiné si plusieurs scanners critiques ───────────
    crit_scanners = [s for s,incs in scanners.items()
                     if any(i['severity']=='CRITICAL' for i in incs)]
    if len(crit_scanners) >= 2:
        prob_combined = min(99, sum(
            compute_base_prob([i for i in scanners[s] if i['severity']=='CRITICAL'])
            for s in crit_scanners
        ))
        combined_steps = [
            {"stage":1, "action":f"Reconnaissance multi-vecteurs ({'+'.join(crit_scanners)})",
             "technique":"T1592", "asset": repo,
             "detail": f"Plusieurs scanners signalent des findings CRITICAL simultanément"},
        ]
        stage = 2
        for s in crit_scanners:
            mi = SCANNER_MITRE.get(s, SCANNER_MITRE['custom'])
            combined_steps.append({
                "stage": stage,
                "action": f"Exploitation {s.upper()} findings",
                "technique": mi['default'],
                "asset": "Application layer",
                "detail": mi['label']
            })
            stage += 1
        combined_steps.append({
            "stage": stage, "action": "Full compromise — persistance + exfiltration",
            "technique": "T1041", "asset": "Infrastructure complète",
            "detail": "Combinaison des vecteurs pour compromission totale"
        })

        paths.append({
            "id": f"build{build}-combined",
            "source": "devsecops",
            "build": build,
            "repo": repo,
            "scanner": "combined",
            "title": f"Multi-Vector Attack — Build #{build}",
            "trigger": f"Scanners critiques simultanés: {', '.join(crit_scanners)}",
            "probability": prob_combined,
            "severity": "CRITICAL",
            "days_to_exploit": 1,
            "patch_priority": "P0-IMMEDIATE",
            "mitre_chain": list(set(
                SCANNER_MITRE.get(s,SCANNER_MITRE['custom'])['default']
                for s in crit_scanners
            )) + ["T1041"],
            "mitre_label": "Multi-vector attack chain",
            "steps": combined_steps,
            "recommendations": [
                f"⛔ STOPPER le déploiement Build #{build}",
                f"Traiter SIMULTANÉMENT les findings de: {', '.join(crit_scanners)}",
                "Déclencher le plan de réponse aux incidents",
                "Isoler l'environnement si déjà déployé en production"
            ],
            "stats": {
                "total": sum(len(scanners[s]) for s in crit_scanners),
                "critical": sum(
                    sum(1 for i in scanners[s] if i['severity']=='CRITICAL')
                    for s in crit_scanners
                ),
                "scanners": crit_scanners
            },
            "ml_prediction": {
                "model": ml_result.get("model"),
                "raw_probability": ml_prob,
                "confidence": ml_confidence,
                "top_features": ml_features
            }
        })

    return sorted(paths, key=lambda x: x['probability'], reverse=True)


def register_devsecops_attack_routes(app):
    from flask import request, jsonify

    @app.route("/api/v1/devsecops/attack-paths")
    def api_devsecops_attack_paths():
        build = request.args.get("build", "")

        if build:
            paths = predict_build_attack_paths(build)
        else:
            with get_conn() as c:
                builds = c.execute("""
                    SELECT DISTINCT json_extract(details,'$.build') as b
                    FROM incident
                    WHERE json_extract(details,'$.build') IS NOT NULL
                    ORDER BY CAST(json_extract(details,'$.build') AS INTEGER) DESC
                """).fetchall()
            paths = []
            for row in builds:
                paths.extend(predict_build_attack_paths(row[0]))

        return jsonify({
            "paths": sorted(paths, key=lambda x: x['probability'], reverse=True),
            "total": len(paths),
            "critical": sum(1 for p in paths if p['severity']=='CRITICAL'),
            "build": build or "all"
        })
