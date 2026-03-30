"""
pipeline.py — Pipeline CTI Cloud-Native complet
Flux : Sources OSINT → Collecte → Parsing → Enrichissement → OpenCTI → Dashboard → Recommandations
"""
import time, schedule, threading
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()


def log(stage: str, msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{stage}] {msg}")


# ─────────────────────────────────────────────
# ÉTAPE 1 — COLLECTE SOURCES OSINT
# ─────────────────────────────────────────────

def step1_collect():
    log("COLLECT", "Démarrage collecte multi-sources...")

    # CVE cloud (NVD API)
    try:
        from nvd_collector import run_collector
        n = run_collector(days_back=1)
        log("COLLECT", f"NVD API → {n} CVE collectées")
    except Exception as e:
        log("COLLECT", f"NVD erreur: {e}")

    # IOC dynamiques (GitHub + Abuse.ch + OTX + GuardDuty)
    try:
        from ioc_collector import run_ioc_collector
        n = run_ioc_collector()
        log("COLLECT", f"IOC multi-sources → {n} IOC collectés")
    except Exception as e:
        log("COLLECT", f"IOC erreur: {e}")


# ─────────────────────────────────────────────
# ÉTAPE 2 — PARSING / EXTRACTION
# ─────────────────────────────────────────────

def step2_parse():
    log("PARSE", "Parsing et extraction des données...")
    from database import get_conn
    from ml_models import cluster_cve, predict_severity, detect_anomaly

    # Clusteriser les nouvelles CVE
    try:
        with get_conn() as c:
            cves = c.execute(
                "SELECT id, description FROM cve WHERE description IS NOT NULL LIMIT 50"
            ).fetchall()
        for cve in cves:
            cl = cluster_cve(cve["description"] or "")
            log("PARSE", f"CVE {cve['id']} → Cluster: {cl['cluster_name']}")
    except Exception as e:
        log("PARSE", f"Clustering erreur: {e}")

    # Prédire sévérité ML sur incidents non traités
    try:
        with get_conn() as c:
            incs = c.execute(
                "SELECT id, event_type, source, triggered_at FROM incident "
                "WHERE ml_severity IS NULL LIMIT 20"
            ).fetchall()
        for inc in incs:
            ml = predict_severity(inc["event_type"], inc["source"], inc["triggered_at"])
            anom = detect_anomaly(60.0, 0.1, 10, 12)
            with get_conn() as c:
                c.execute(
                    "UPDATE incident SET ml_severity=?, anomaly_score=? WHERE id=?",
                    (ml["severity"], anom["anomaly_score"], inc["id"])
                )
        log("PARSE", f"{len(incs)} incidents enrichis avec ML")
    except Exception as e:
        log("PARSE", f"ML parsing erreur: {e}")


# ─────────────────────────────────────────────
# ÉTAPE 3 — ENRICHISSEMENT IOC
# ─────────────────────────────────────────────

def step3_enrich():
    log("ENRICH", "Enrichissement IOC via VirusTotal...")
    from database import get_conn
    from virustotal import enrich_ioc
    from ml_models import score_ioc

    try:
        with get_conn() as c:
            iocs = c.execute(
                "SELECT i.type, i.value FROM ioc i "
                "LEFT JOIN enrichment e ON i.value = e.ioc_value "
                "WHERE e.ioc_value IS NULL LIMIT 10"
            ).fetchall()

        for ioc in iocs:
            result = enrich_ioc(ioc["value"], ioc["type"])
            # Scorer avec ML
            ml_result = score_ioc(
                ioc["value"], ioc["type"],
                result.get("score", 0),
                result.get("malicious_count", 0),
                result.get("total_engines", 70)
            )
            log("ENRICH", f"{ioc['type']} {ioc['value'][:30]} → "
                          f"VT:{result.get('score',0)}% ML:{ml_result['label']}")

        log("ENRICH", f"{len(iocs)} IOC enrichis")
    except Exception as e:
        log("ENRICH", f"Enrichissement erreur: {e}")


# ─────────────────────────────────────────────
# ÉTAPE 4 — NORMALISATION STIX 2.1 + TLP
# ─────────────────────────────────────────────

def step4_normalize():
    log("STIX", "Normalisation STIX 2.1 + classification TLP...")
    from database import get_conn
    from stix_normalizer import cve_to_stix, ioc_to_stix, export_bundle
    import os

    objects = []
    try:
        with get_conn() as c:
            cves = c.execute(
                "SELECT * FROM cve WHERE severity IN ('CRITICAL','HIGH') "
                "ORDER BY created_at DESC LIMIT 20"
            ).fetchall()
            iocs = c.execute(
                "SELECT * FROM ioc ORDER BY created_at DESC LIMIT 20"
            ).fetchall()

        for cve in cves:
            stix = cve_to_stix(dict(cve))
            objects.append(stix["object"])

        for ioc in iocs:
            stix = ioc_to_stix(dict(ioc))
            if stix:
                objects.append(stix["object"])

        if objects:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            path = f"data/stix_bundles/bundle_{ts}.json"
            os.makedirs("data/stix_bundles", exist_ok=True)
            export_bundle(objects, path)
            log("STIX", f"{len(objects)} objets STIX 2.1 exportés → {path}")

    except Exception as e:
        log("STIX", f"Normalisation erreur: {e}")


# ─────────────────────────────────────────────
# ÉTAPE 5 — PUSH VERS OPENCTI
# ─────────────────────────────────────────────

def step5_push_opencti():
    log("OpenCTI", "Synchronisation vers OpenCTI...")
    try:
        from opencti_connector import sync_all
        n = sync_all()
        log("OpenCTI", f"{n} objets pushés vers OpenCTI")
    except Exception as e:
        log("OpenCTI", f"Push erreur: {e}")


# ─────────────────────────────────────────────
# ÉTAPE 6 — RECOMMANDATIONS
# ─────────────────────────────────────────────

def step6_recommendations():
    log("RECO", "Génération recommandations posture sécurité...")
    from database import get_conn, insert_recommendation

    try:
        with get_conn() as c:
            # CVE critiques sans recommandation
            cves = c.execute(
                "SELECT id, cvss_score, severity FROM cve "
                "WHERE severity='CRITICAL' AND id NOT IN "
                "(SELECT ref_id FROM recommendation WHERE ref_type='cve') "
                "LIMIT 10"
            ).fetchall()

            # IOC malveillants sans recommandation
            malicious = c.execute(
                "SELECT DISTINCT e.ioc_value FROM enrichment e "
                "WHERE e.score > 70 AND e.ioc_value NOT IN "
                "(SELECT ref_id FROM recommendation WHERE ref_type='ioc') "
                "LIMIT 10"
            ).fetchall()

            # Incidents CRITICAL sans recommandation
            incidents = c.execute(
                "SELECT id, event_type, repo FROM incident "
                "WHERE severity='CRITICAL' AND id NOT IN "
                "(SELECT ref_id FROM recommendation WHERE ref_type='incident') "
                "LIMIT 5"
            ).fetchall()

        count = 0
        for cve in cves:
            insert_recommendation({
                "ref_id":      cve["id"],
                "ref_type":    "cve",
                "priority":    "critical",
                "title":       f"Patch urgent : {cve['id']} (CVSS {cve['cvss_score']})",
                "description": "CVE critique cloud — appliquer le patch dans les 24h sur tous les environnements.",
                "mitre_id":    "T1190",
            })
            count += 1

        for ioc in malicious:
            insert_recommendation({
                "ref_id":      ioc["ioc_value"],
                "ref_type":    "ioc",
                "priority":    "high",
                "title":       f"Bloquer IOC malveillant : {ioc['ioc_value'][:40]}",
                "description": "IOC avec score VirusTotal > 70% — bloquer sur firewall et SIEM.",
                "mitre_id":    "T1071",
            })
            count += 1

        for inc in incidents:
            insert_recommendation({
                "ref_id":      str(inc["id"]),
                "ref_type":    "incident",
                "priority":    "critical",
                "title":       f"Incident critique CI/CD : {inc['event_type']} sur {inc['repo']}",
                "description": "Révoquer les credentials exposés, auditer le pipeline CI/CD, notifier le RSSI.",
                "mitre_id":    "T1552.001",
            })
            count += 1

        log("RECO", f"{count} nouvelles recommandations générées")

    except Exception as e:
        log("RECO", f"Recommandations erreur: {e}")


# ─────────────────────────────────────────────
# PIPELINE COMPLET
# ─────────────────────────────────────────────

def run_pipeline():
    """Exécute le pipeline CTI complet."""
    print("\n" + "="*55)
    print("  CTI PIPELINE — Flux complet automatisé")
    print("  Sources → Parse → Enrich → STIX → OpenCTI → Reco")
    print("="*55)

    steps = [
        ("1. Collecte OSINT",         step1_collect),
        ("2. Parsing & ML",           step2_parse),
        ("3. Enrichissement IOC",     step3_enrich),
        ("4. Normalisation STIX 2.1", step4_normalize),
        ("5. Push OpenCTI",           step5_push_opencti),
        ("6. Recommandations",        step6_recommendations),
    ]

    for name, fn in steps:
        print(f"\n{'─'*40}")
        print(f"  ► {name}")
        print(f"{'─'*40}")
        try:
            fn()
        except Exception as e:
            log("PIPELINE", f"Erreur étape '{name}': {e}")

    print("\n" + "="*55)
    print("  Pipeline terminé ✓")
    print("="*55)


# ─────────────────────────────────────────────
# SCHEDULER AUTOMATIQUE
# ─────────────────────────────────────────────

def start_scheduler():
    """Lance le pipeline automatiquement selon le schedule."""
    schedule.every(1).hours.do(run_pipeline)
    schedule.every(6).hours.do(step1_collect)   # Collecte plus fréquente
    schedule.every(30).minutes.do(step5_push_opencti)

    print("[SCHEDULER] Pipeline CTI actif")
    print("[SCHEDULER] Collecte : toutes les heures")
    print("[SCHEDULER] Push OpenCTI : toutes les 30 min")

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    from database import init_db
    init_db()
    run_pipeline()

def step3_enrich_auto():
    """Enrichissement automatique de tous les nouveaux IOC via VirusTotal."""
    import time
    from virustotal import enrich_ioc
    from database import get_conn, insert_enrichment
    from ml_models import score_ioc

    with get_conn() as c:
        iocs = c.execute(
            "SELECT i.type, i.value FROM ioc i "
            "LEFT JOIN enrichment e ON i.value=e.ioc_value "
            "WHERE e.ioc_value IS NULL LIMIT 10"
        ).fetchall()

    if not iocs:
        log("ENRICH", "Tous les IOC sont déjà enrichis")
        return 0

    count = 0
    for ioc in iocs:
        result = enrich_ioc(ioc["value"], ioc["type"])
        ml = score_ioc(ioc["value"], ioc["type"],
                       result["score"],
                       result["malicious_count"],
                       result["total_engines"])
        insert_enrichment({
            "ioc_value":       ioc["value"],
            "provider":        "virustotal",
            "score":           result["score"],
            "malicious_count": result["malicious_count"],
            "total_engines":   result["total_engines"],
            "tags":            "[]",
        })
        log("ENRICH", f'{ioc["type"]:8} VT:{result["score"]:5.1f}% ML:{ml["label"]} — {ioc["value"][:35]}')
        count += 1
        time.sleep(15)  # rate limit VT gratuit

    log("ENRICH", f"{count} IOC enrichis automatiquement")
    return count
