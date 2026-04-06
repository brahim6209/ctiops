"""
auto_scheduler.py — Collecte automatique et continue
Toutes les sources sont viables, dynamiques et auto-actualisées
"""
import threading
import time
import schedule
import datetime
import json
from database import get_conn

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[SCHEDULER {ts}] {msg}")

# ── TÂCHE 1 : CVE Cloud — toutes les 6h ──────────────────────────
def task_collect_cves():
    log("CVE collection started...")
    try:
        from nvd_collector import run_collector
        r = run_collector(days_back=7)
        log(f"CVE done: NVD={r.get('nvd',0)} CISA={r.get('cisa',0)}")
    except Exception as e:
        log(f"CVE error: {e}")

# ── TÂCHE 2 : Enrichissement CVE — après chaque collecte ──────────
def task_enrich_cves():
    log("CVE enrichment started...")
    try:
        from cve_enricher import enrich_all_cves
        r = enrich_all_cves(limit=200, use_vt=False)
        log(f"Enriched: {r.get('enriched',0)} CVEs | Types: {r.get('types',{})}")
    except Exception as e:
        log(f"Enrichment error: {e}")

# ── TÂCHE 3 : IOC Collection — toutes les 3h ─────────────────────
def task_collect_iocs():
    log("IOC collection started...")
    try:
        from threat_intel import fetch_urlhaus, fetch_feodo, fetch_threatfox
        u = fetch_urlhaus(200)
        f = fetch_feodo()
        t = fetch_threatfox(3)
        log(f"IOC done: URLhaus={u} Feodo={f} ThreatFox={t}")
    except Exception as e:
        log(f"IOC error: {e}")

# ── TÂCHE 4 : VT Verification — toutes les 2h ────────────────────
def task_verify_vt():
    log("VirusTotal verification started...")
    try:
        from threat_intel import verify_all_pending_iocs
        r = verify_all_pending_iocs(limit=50)
        log(f"VT done: verified={r.get('verified',0)} malicious={r.get('malicious',0)} suspicious={r.get('suspicious',0)}")
    except Exception as e:
        log(f"VT error: {e}")

# ── TÂCHE 5 : MISP Sync — toutes les 2h ──────────────────────────
def task_misp_sync():
    log("MISP sync started...")
    try:
        from misp_connector import push_cves, push_incidents
        c = push_cves(limit=10)
        i = push_incidents(limit=20)
        log(f"MISP done: CVE={c} incidents={i}")
    except Exception as e:
        log(f"MISP error: {e}")

# ── TÂCHE 6 : CISA KEV update — toutes les 24h ───────────────────
def task_update_kev():
    log("CISA KEV update started...")
    try:
        import requests
        r = requests.get(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            timeout=30
        )
        vulns = r.json()['vulnerabilities']
        kev_ids = {v['cveID'] for v in vulns}
        updated = 0
        with get_conn() as c:
            for cve_id in kev_ids:
                res = c.execute(
                    "UPDATE cve SET actively_exploited=1, exploit_source='CISA-KEV' WHERE id=? AND actively_exploited=0",
                    (cve_id,)
                )
                if res.rowcount > 0:
                    updated += 1
        log(f"KEV update done: {updated} new KEV CVEs | Total catalog: {len(kev_ids)}")
    except Exception as e:
        log(f"KEV update error: {e}")

# ── TÂCHE 7 : EPSS Update — toutes les 24h ───────────────────────
def task_update_epss():
    log("EPSS update started...")
    try:
        import requests, gzip, io, csv
        # EPSS scores — updated daily by FIRST.org
        r = requests.get(
            "https://epss.cyentia.com/epss_scores-current.csv.gz",
            timeout=60
        )
        if r.status_code == 200:
            with gzip.open(io.BytesIO(r.content)) as f:
                reader = csv.reader(io.TextIOWrapper(f))
                next(reader)  # skip header comment
                next(reader)  # skip column names
                updated = 0
                with get_conn() as c:
                    for row in reader:
                        if len(row) >= 2:
                            cve_id, epss_score = row[0], row[1]
                            try:
                                res = c.execute(
                                    "UPDATE cve SET epss_score=? WHERE id=?",
                                    (float(epss_score), cve_id)
                                )
                                if res.rowcount > 0:
                                    updated += 1
                            except:
                                pass
            log(f"EPSS update done: {updated} CVEs updated")
        else:
            log(f"EPSS HTTP error: {r.status_code}")
    except Exception as e:
        log(f"EPSS update error: {e}")

# ── TÂCHE 8 : Stats snapshot — toutes les heures ─────────────────
def task_snapshot_stats():
    try:
        with get_conn() as c:
            total  = c.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            kev    = c.execute("SELECT COUNT(*) FROM cve WHERE actively_exploited=1").fetchone()[0]
            ioc    = c.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
            inc    = c.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
        log(f"Stats: CVE={total} KEV={kev} IOC={ioc} Incidents={inc}")
    except Exception as e:
        log(f"Stats error: {e}")

# ── RUNNER ────────────────────────────────────────────────────────
def run_scheduler():
    """Démarrer le scheduler en arrière-plan."""
    log("Scheduler starting...")

    # Planifier les tâches
    schedule.every(6).hours.do(task_collect_cves)
    schedule.every(6).hours.do(task_enrich_cves)
    schedule.every(3).hours.do(task_collect_iocs)
    schedule.every(2).hours.do(task_verify_vt)
    schedule.every(2).hours.do(task_misp_sync)
    schedule.every(24).hours.do(task_update_kev)
    schedule.every(24).hours.do(task_update_epss)
    schedule.every(1).hours.do(task_snapshot_stats)

    # Exécuter immédiatement au démarrage
    log("Running initial tasks...")
    threading.Thread(target=task_collect_iocs, daemon=True).start()
    time.sleep(2)
    threading.Thread(target=task_enrich_cves, daemon=True).start()
    time.sleep(2)
    threading.Thread(target=task_update_kev, daemon=True).start()
    time.sleep(2)
    threading.Thread(target=task_misp_sync, daemon=True).start()
    time.sleep(2)
    threading.Thread(target=task_update_epss, daemon=True).start()

    log("Scheduler running — all tasks scheduled")

    # Boucle principale
    while True:
        schedule.run_pending()
        time.sleep(30)

def start_scheduler_thread():
    """Démarrer le scheduler dans un thread daemon."""
    t = threading.Thread(target=run_scheduler, daemon=True, name="CTI-Scheduler")
    t.start()
    return t

if __name__ == "__main__":
    run_scheduler()
